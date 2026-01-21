# Prevent Sinatra from parsing command-line arguments that might cause issues
# We'll configure the port and bind address directly in code
ARGV.clear if ARGV.any?

require 'sinatra'
require 'stripe'
require 'dotenv'
require 'json'
require 'sinatra/cross_origin'

# Set the port from environment variable or default to 4567
# This ensures compatibility with Railway, Render, Heroku, and other platforms
set :port, ENV['PORT'] ? ENV['PORT'].to_i : 4567
set :bind, '0.0.0.0'

# Browsers require that external servers enable CORS when the server is at a different origin than the website.
# https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
# This enables the requires CORS headers to allow the browser to make the requests from the JS Example App.
configure do
  enable :cross_origin
end

before do
  response.headers['Access-Control-Allow-Origin'] = '*'
  
  # Parse JSON request body if Content-Type is application/json
  if request.content_type && request.content_type.include?('application/json') && request.body.size > 0
    request.body.rewind
    body_content = request.body.read
    if !body_content.empty?
      begin
        json_params = JSON.parse(body_content)
        # Merge JSON params into params hash
        json_params.each { |k, v| params[k.to_sym] = v }
      rescue JSON::ParserError => e
        # If JSON parsing fails, continue with existing params
        log_info("Failed to parse JSON body: #{e.message}")
      end
    end
  end
end

options "*" do
  response.headers["Allow"] = "GET, POST, OPTIONS"
  response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, Accept, X-User-Email, X-Auth-Token"
  response.headers["Access-Control-Allow-Origin"] = "*"
  200
end

# Load .env file if it exists (for local development)
Dotenv.load if File.exist?('.env')

Stripe.api_key = ENV['STRIPE_ENV'] == 'production' ? ENV['STRIPE_SECRET_KEY'] : ENV['STRIPE_TEST_SECRET_KEY']
Stripe.api_version = '2020-03-02'

def log_info(message)
  puts "\n" + message + "\n\n"
  return message
end

get '/' do
  status 200
  send_file 'index.html'
end

def validateApiKey
  if Stripe.api_key.nil? || Stripe.api_key.empty?
    return "Error: you provided an empty secret key. Please provide your test mode secret key. For more information, see https://stripe.com/docs/keys"
  end
  if Stripe.api_key.start_with?('pk')
    return "Error: you used a publishable key to set up the example backend. Please use your test mode secret key. For more information, see https://stripe.com/docs/keys"
  end
  if Stripe.api_key.start_with?('sk_live')
    return "Error: you used a live mode secret key to set up the example backend. Please use your test mode secret key. For more information, see https://stripe.com/docs/keys#test-live-modes"
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

# This endpoint retrieves the current status of a PaymentIntent.
# Useful for polling from the frontend to check Terminal payment status.
# https://stripe.com/docs/api/payment_intents/retrieve
get '/payment_intent/:id' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_info(validationError)
  end

  begin
    payment_intent = Stripe::PaymentIntent.retrieve(params[:id])
  rescue Stripe::StripeError => e
    status 402
    return log_info("Error retrieving PaymentIntent! #{e.message}")
  end

  status 200
  content_type :json
  return payment_intent.to_json
end

# This endpoint handles Stripe webhook events.
# Configure this URL in your Stripe Dashboard: https://dashboard.stripe.com/webhooks
# https://stripe.com/docs/webhooks
post '/webhook' do
  payload = request.body.read
  sig_header = request.env['HTTP_STRIPE_SIGNATURE']
  endpoint_secret = ENV['STRIPE_WEBHOOK_SECRET']

  begin
    event = Stripe::Webhook.construct_event(
      payload, sig_header, endpoint_secret
    )
  rescue JSON::ParserError => e
    log_info("Invalid payload: #{e.message}")
    status 400
    return "Invalid payload"
  rescue Stripe::SignatureVerificationError => e
    log_info("Invalid signature: #{e.message}")
    status 400
    return "Invalid signature"
  end

  # Handle the event
  case event.type
  when 'payment_intent.succeeded'
    payment_intent = event.data.object
    log_info("PaymentIntent succeeded: #{payment_intent.id}")
    # You can add custom logic here, e.g., update your database, send notifications, etc.
    
  when 'payment_intent.payment_failed'
    payment_intent = event.data.object
    log_info("PaymentIntent failed: #{payment_intent.id}")
    # Handle failed payment
    
  when 'charge.succeeded'
    charge = event.data.object
    log_info("Charge succeeded: #{charge.id}")
    
  when 'charge.captured'
    charge = event.data.object
    log_info("Charge captured: #{charge.id}")
    
  when 'payment_intent.amount_capturable_updated'
    payment_intent = event.data.object
    log_info("PaymentIntent amount_capturable updated: #{payment_intent.id}")
    
  else
    log_info("Unhandled event type: #{event.type}")
  end

  status 200
  return {:received => true}.to_json
end
