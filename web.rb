# Prevent Sinatra from parsing command-line arguments that might cause issues
# We'll configure the port and bind address directly in code
ARGV.clear if ARGV.any?

require 'sinatra'
require 'stripe'
require 'dotenv'
require 'json'
require 'sinatra/cross_origin'
require 'rack/protection'

# Set the port from environment variable or default to 4567
# This ensures compatibility with Railway, Render, Heroku, and other platforms
set :port, ENV['PORT'] ? ENV['PORT'].to_i : 4567
set :bind, '0.0.0.0'

# Load environment variables
# Load .env file if it exists (for local development)
Dotenv.load if File.exist?('.env')

# Production/Environment Configuration
PRODUCTION = ENV['RACK_ENV'] == 'production' || ENV['ENVIRONMENT'] == 'production'
STRIPE_ENV = ENV['STRIPE_ENV'] || (PRODUCTION ? 'production' : 'test')

# Stripe Configuration
if STRIPE_ENV == 'production'
  Stripe.api_key = ENV['STRIPE_SECRET_KEY'] || ENV['STRIPE_LIVE_SECRET_KEY']
else
  Stripe.api_key = ENV['STRIPE_TEST_SECRET_KEY']
end
Stripe.api_version = '2020-03-02'

# Production Configuration Validation
if PRODUCTION
  if Stripe.api_key.nil? || Stripe.api_key.empty? || !Stripe.api_key.start_with?('sk_live')
    puts "\n⚠️  WARNING: STRIPE_SECRET_KEY should be set to your live key (sk_live_...) in production!\n\n"
  end
end

# Security: Enable protection against common attacks
configure do
  enable :cross_origin
  enable :sessions
  set :protection, :except => [:json_csrf] # CORS handles cross-origin for API
end

# CORS Configuration - Allow all origins
before do
  response.headers['Access-Control-Allow-Origin'] = '*'
  response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
  response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type, Accept'
  response.headers['Access-Control-Max-Age'] = '3600'
  
  # Security headers
  response.headers['X-Content-Type-Options'] = 'nosniff'
  response.headers['X-Frame-Options'] = 'DENY'
  response.headers['X-XSS-Protection'] = '1; mode=block'
  if PRODUCTION
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
  end
end

options "*" do
  response.headers["Allow"] = "GET, POST, OPTIONS"
  response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, Accept, X-User-Email, X-Auth-Token"
  response.headers["Access-Control-Allow-Origin"] = "*"
  status 200
end

def log_info(message)
  puts "\n" + message + "\n\n"
  return message
end

get '/' do
  status 404
  content_type :json
  {:error => 'Not Found', :message => 'This service is not available.'}.to_json
end

def validateApiKey
  if Stripe.api_key.nil? || Stripe.api_key.empty?
    mode = STRIPE_ENV == 'production' ? 'production' : 'test'
    return "Error: you provided an empty secret key. Please provide your #{mode} mode secret key. For more information, see https://stripe.com/docs/keys"
  end
  if Stripe.api_key.start_with?('pk')
    return "Error: you used a publishable key to set up the backend. Please use your secret key. For more information, see https://stripe.com/docs/keys"
  end
  # Production validation: ensure key matches environment
  if STRIPE_ENV == 'production'
    unless Stripe.api_key.start_with?('sk_live')
      return "Error: you are in production mode but using a test key. Please use your live mode secret key (sk_live_...). For more information, see https://stripe.com/docs/keys#test-live-modes"
    end
  else
    # Test mode: ensure key matches environment
    if Stripe.api_key.start_with?('sk_live')
      return "Error: you are in test mode but using a live key. Please use your test mode secret key (sk_test_...). For more information, see https://stripe.com/docs/keys#test-live-modes"
    end
    unless Stripe.api_key.start_with?('sk_test')
      return "Error: invalid secret key format. Please use your test mode secret key (sk_test_...). For more information, see https://stripe.com/docs/keys"
    end
  end
  return nil
end

# This endpoint registers a Verifone P400 reader to your Stripe account.
# https://stripe.com/docs/terminal/readers/connecting/verifone-p400#register-reader
post '/register_reader' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_info(validationError)
  end

  begin
    reader = Stripe::Terminal::Reader.create(
      :registration_code => params[:registration_code],
      :label => params[:label],
      :location => params[:location]
    )
  rescue Stripe::StripeError => e
    status 402
    return log_info("Error registering reader! #{e.message}")
  end

  log_info("Reader registered: #{reader.id}")

  status 200
  # Note that returning the Stripe reader object directly creates a dependency between your
  # backend's Stripe.api_version and your clients, making future upgrades more complicated.
  # All clients must also be ready for backwards-compatible changes at any time:
  # https://stripe.com/docs/upgrades#what-changes-does-stripe-consider-to-be-backwards-compatible
  return reader.to_json
end

# This endpoint creates a ConnectionToken, which gives the SDK permission
# to use a reader with your Stripe account.
# https://stripe.com/docs/terminal/sdk/js#connection-token
# https://stripe.com/docs/terminal/sdk/ios#connection-token
# https://stripe.com/docs/terminal/sdk/android#connection-token
#
# The example backend does not currently support connected accounts.
# To create a ConnectionToken for a connected account, see
# https://stripe.com/docs/terminal/features/connect#direct-connection-tokens
post '/connection_token' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_info(validationError)
  end

  begin
    token = Stripe::Terminal::ConnectionToken.create
  rescue Stripe::StripeError => e
    status 402
    return log_info("Error creating ConnectionToken! #{e.message}")
  end

  content_type :json
  status 200
  return {:secret => token.secret}.to_json
end

# This endpoint creates a PaymentIntent.
# https://stripe.com/docs/terminal/payments#create
#
# The example backend does not currently support connected accounts.
# To create a PaymentIntent for a connected account, see
# https://stripe.com/docs/terminal/features/connect#direct-payment-intents-server-side
# Looks up or creates a Customer on your stripe account with the provided email
def lookupOrCreateCustomer(customerEmail)
  return nil if customerEmail.nil? || customerEmail.empty?
  
  begin
    customerList = Stripe::Customer.list(email: customerEmail, limit: 1).data
    if (customerList.length == 1)
      return customerList[0]
    else
      return Stripe::Customer.create(email: customerEmail)
    end
  rescue Stripe::StripeError => e
    log_info("Error creating or retrieving customer! #{e.message}")
    return nil
  end
end

post '/create_payment_intent' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_info(validationError)
  end

  begin
    # Get email from request
    customer_email = params[:email] || params[:receipt_email]
    
    # Look up or create Stripe Customer from email
    customer = nil
    if customer_email
      customer = lookupOrCreateCustomer(customer_email)
    end
    
    payment_intent_params = {
      :payment_method_types => params[:payment_method_types] || ['card_present'],
      :capture_method => params[:capture_method] || 'manual',
      :amount => params[:amount],
      :currency => params[:currency] || 'usd',
      :description => params[:description] || 'Example PaymentIntent',
      :payment_method_options => params[:payment_method_options] || [],
      :receipt_email => customer_email,
    }
    
    # Add customer if we have one
    if customer
      payment_intent_params[:customer] = customer.id
    end
    
    # Add metadata if provided
    if params[:metadata] && !params[:metadata].empty?
      payment_intent_params[:metadata] = params[:metadata]
    end
    
    payment_intent = Stripe::PaymentIntent.create(payment_intent_params)
    
    # Update description to only contain the PaymentIntent ID
    payment_intent = Stripe::PaymentIntent.update(
      payment_intent.id,
      description: payment_intent.id
    )
  rescue Stripe::StripeError => e
    status 402
    return log_info("Error creating PaymentIntent! #{e.message}")
  end

  log_info("PaymentIntent successfully created: #{payment_intent.id}")
  status 200
  return {:intent => payment_intent.id, :secret => payment_intent.client_secret}.to_json
end

# This endpoint captures a PaymentIntent.
# https://stripe.com/docs/terminal/payments#capture
post '/capture_payment_intent' do
  begin
    id = params["payment_intent_id"]
    if !params["amount_to_capture"].nil?
      payment_intent = Stripe::PaymentIntent.capture(id, :amount_to_capture => params["amount_to_capture"])
    else
      payment_intent = Stripe::PaymentIntent.capture(id)
    end
  rescue Stripe::StripeError => e
    status 402
    return log_info("Error capturing PaymentIntent! #{e.message}")
  end

  log_info("PaymentIntent successfully captured: #{id}")
  # Optionally reconcile the PaymentIntent with your internal order system.
  status 200
  return {:intent => payment_intent.id, :secret => payment_intent.client_secret}.to_json
end

# This endpoint cancels a PaymentIntent.
# https://stripe.com/docs/api/payment_intents/cancel
post '/cancel_payment_intent' do
  begin
    id = params["payment_intent_id"]
    payment_intent = Stripe::PaymentIntent.cancel(id)
  rescue Stripe::StripeError => e
    status 402
    return log_info("Error canceling PaymentIntent! #{e.message}")
  end

  log_info("PaymentIntent successfully canceled: #{id}")
  # Optionally reconcile the PaymentIntent with your internal order system.
  status 200
  return {:intent => payment_intent.id, :secret => payment_intent.client_secret}.to_json
end

# This endpoint creates a SetupIntent.
# https://stripe.com/docs/api/setup_intents/create
post '/create_setup_intent' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_info(validationError)
  end

  begin
    setup_intent_params = {
      :payment_method_types => params[:payment_method_types] || ['card_present'],
    }

    if !params[:customer].nil?
      setup_intent_params[:customer] = params[:customer]
    end

    if !params[:description].nil?
      setup_intent_params[:description] = params[:description]
    end

    if !params[:on_behalf_of].nil?
      setup_intent_params[:on_behalf_of] = params[:on_behalf_of]
    end

    setup_intent = Stripe::SetupIntent.create(setup_intent_params)

  rescue Stripe::StripeError => e
    status 402
    return log_info("Error creating SetupIntent! #{e.message}")
  end

  log_info("SetupIntent successfully created: #{setup_intent.id}")
  status 200
  return {:intent => setup_intent.id, :secret => setup_intent.client_secret}.to_json
end

# Looks up or creates a Customer on your stripe account
# with email "example@test.com".
def lookupOrCreateExampleCustomer
  customerEmail = "example@test.com"
  begin
    customerList = Stripe::Customer.list(email: customerEmail, limit: 1).data
    if (customerList.length == 1)
      return customerList[0]
    else
      return Stripe::Customer.create(email: customerEmail)
    end
  rescue Stripe::StripeError => e
    status 402
    return log_info("Error creating or retreiving customer! #{e.message}")
  end
end

# This endpoint attaches a PaymentMethod to a Customer.
# https://stripe.com/docs/terminal/payments/saving-cards#read-reusable-card
post '/attach_payment_method_to_customer' do
  begin
    customer = lookupOrCreateExampleCustomer

    payment_method = Stripe::PaymentMethod.attach(
      params[:payment_method_id],
      {
        customer: customer.id,
        expand: ["customer"],
    })
  rescue Stripe::StripeError => e
    status 402
    return log_info("Error attaching PaymentMethod to Customer! #{e.message}")
  end

  log_info("Attached PaymentMethod to Customer: #{customer.id}")

  status 200
  # Note that returning the Stripe payment_method object directly creates a dependency between your
  # backend's Stripe.api_version and your clients, making future upgrades more complicated.
  # All clients must also be ready for backwards-compatible changes at any time:
  # https://stripe.com/docs/upgrades#what-changes-does-stripe-consider-to-be-backwards-compatible
  return payment_method.to_json
end

# This endpoint updates the PaymentIntent represented by 'payment_intent_id'.
# It currently only supports updating the 'receipt_email' property.
#
# https://stripe.com/docs/api/payment_intents/update
post '/update_payment_intent' do
  payment_intent_id = params["payment_intent_id"]
  if payment_intent_id.nil?
    status 400
    return log_info("'payment_intent_id' is a required parameter")
  end

  begin
    allowed_keys = ["receipt_email"]
    update_params = params.select { |k, _| allowed_keys.include?(k) }

    payment_intent = Stripe::PaymentIntent.update(
      payment_intent_id,
      update_params
    )

    log_info("Updated PaymentIntent #{payment_intent_id}")
  rescue Stripe::StripeError => e
    status 402
    return log_info("Error updating PaymentIntent #{payment_intent_id}. #{e.message}")
  end

  status 200
  return {:intent => payment_intent.id, :secret => payment_intent.client_secret}.to_json
end

# This endpoint lists the first 100 Locations. If you will have more than 100
# Locations, you'll likely want to implement pagination in your application so that
# you can efficiently fetch Locations as needed.
# https://stripe.com/docs/api/terminal/locations
get '/list_locations' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_info(validationError)
  end

  begin
    locations = Stripe::Terminal::Location.list(
      limit: 100
    )
  rescue Stripe::StripeError => e
    status 402
    return log_info("Error fetching Locations! #{e.message}")
  end

  log_info("#{locations.data.size} Locations successfully fetched")

  status 200
  content_type :json
  return locations.data.to_json
end

# This endpoint creates a Location.
# https://stripe.com/docs/api/terminal/locations
post '/create_location' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_info(validationError)
  end

  begin
    location = Stripe::Terminal::Location.create(
      display_name: params[:display_name],
      address: params[:address]
    )
  rescue Stripe::StripeError => e
    status 402
    return log_info("Error creating Location! #{e.message}")
  end

  log_info("Location successfully created: #{location.id}")

  status 200
  content_type :json
  return location.to_json
end
