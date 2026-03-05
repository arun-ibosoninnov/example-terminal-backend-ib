# Prevent Sinatra from parsing command-line arguments that might cause issues
# We'll configure the port and bind address directly in code
ARGV.clear if ARGV.any?

require 'logger'
require 'sinatra'
require 'stripe'
require 'dotenv'
require 'json'
require 'sinatra/cross_origin'
require 'rack/protection'

# Logger for production; defaults to stderr, level from LOG_LEVEL (default INFO).
APP_LOGGER = Logger.new($stderr).tap do |l|
  l.level = Logger.const_get((ENV['LOG_LEVEL'] || 'INFO').upcase) rescue Logger::INFO
  l.formatter = proc { |sev, _dt, _prog, msg| "[#{sev}] #{msg}\n" }
end

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
    APP_LOGGER.warn("STRIPE_SECRET_KEY should be set to your live key (sk_live_...) in production!")
  end
end

# Security: Enable protection against common attacks
configure do
  enable :cross_origin
  set :protection, :except => [:json_csrf]
end

# CORS and Security Headers
before do
  # In production, restrict CORS to ALLOWED_ORIGINS if set; otherwise allow all (dev/staging)
  if PRODUCTION && ENV['ALLOWED_ORIGINS'] && !ENV['ALLOWED_ORIGINS'].strip.empty?
    allowed = ENV['ALLOWED_ORIGINS'].split(',').map(&:strip)
    origin = request.env['HTTP_ORIGIN']
    if origin && allowed.include?(origin)
      response.headers['Access-Control-Allow-Origin'] = origin
      response.headers['Vary'] = 'Origin'
    elsif !allowed.empty?
      response.headers['Access-Control-Allow-Origin'] = allowed.first
    end
  else
    response.headers['Access-Control-Allow-Origin'] = '*'
  end

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

  content_type :json
end

options "*" do
  response.headers["Allow"] = "GET, POST, OPTIONS"
  response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, Accept, X-User-Email, X-Auth-Token"
  response.headers["Access-Control-Allow-Origin"] = "*"
  status 200
end

def log_info(message)
  APP_LOGGER.info(message.to_s)
end

# Returns the HTTP status from a Stripe error, falling back to 402.
def stripe_error_status(e)
  e.respond_to?(:http_status) && e.http_status ? e.http_status : 402
end

get '/' do
  status 404
  { error: 'Not Found', message: 'This service is not available.' }.to_json
end

# Returns API key validation error message, or nil if valid. Used by require_valid_api_key!
def validate_api_key
  if Stripe.api_key.nil? || Stripe.api_key.empty?
    mode = STRIPE_ENV == 'production' ? 'production' : 'test'
    return "Error: you provided an empty secret key. Please provide your #{mode} mode secret key. For more information, see https://stripe.com/docs/keys"
  end
  if Stripe.api_key.start_with?('pk')
    return "Error: you used a publishable key to set up the backend. Please use your secret key. For more information, see https://stripe.com/docs/keys"
  end
  if STRIPE_ENV == 'production'
    unless Stripe.api_key.start_with?('sk_live')
      return "Error: you are in production mode but using a test key. Please use your live mode secret key (sk_live_...). For more information, see https://stripe.com/docs/keys#test-live-modes"
    end
  else
    if Stripe.api_key.start_with?('sk_live')
      return "Error: you are in test mode but using a live key. Please use your test mode secret key (sk_test_...). For more information, see https://stripe.com/docs/keys#test-live-modes"
    end
    unless Stripe.api_key.start_with?('sk_test')
      return "Error: invalid secret key format. Please use your test mode secret key (sk_test_...). For more information, see https://stripe.com/docs/keys"
    end
  end
  nil
end

# Shared API-key validation: halts with 400 if invalid. Call at the start of protected routes.
def require_valid_api_key!
  err = validate_api_key
  halt 400, { error: err }.to_json if err
end

# This endpoint registers a Verifone P400 reader to your Stripe account.
# https://stripe.com/docs/terminal/readers/connecting/verifone-p400#register-reader
post '/register_reader' do
  require_valid_api_key!
  if params[:registration_code].nil? || params[:registration_code].to_s.strip.empty?
    status 400
    return { error: "'registration_code' is required to register a reader. For more information, see https://stripe.com/docs/terminal/readers/connecting" }.to_json
  end

  begin
    reader = Stripe::Terminal::Reader.create(
      registration_code: params[:registration_code],
      label:             params[:label],
      location:          params[:location]
    )
  rescue Stripe::StripeError => e
    log_info("Error registering reader! #{e.message}")
    status stripe_error_status(e)
    return { error: e.message }.to_json
  end

  log_info("Reader registered: #{reader.id}")
  status 200
  # Note that returning the Stripe reader object directly creates a dependency between your
  # backend's Stripe.api_version and your clients, making future upgrades more complicated.
  # All clients must also be ready for backwards-compatible changes at any time:
  # https://stripe.com/docs/upgrades#what-changes-does-stripe-consider-to-be-backwards-compatible
  reader.to_json
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
  require_valid_api_key!

  begin
    token = Stripe::Terminal::ConnectionToken.create
  rescue Stripe::StripeError => e
    log_info("Error creating ConnectionToken! #{e.message}")
    status stripe_error_status(e)
    return { error: e.message }.to_json
  end

  status 200
  { secret: token.secret }.to_json
end

# Looks up or creates a Customer on your Stripe account with the provided email.
def lookup_or_create_customer(customer_email)
  return nil if customer_email.nil? || customer_email.to_s.strip.empty?

  begin
    customer_list = Stripe::Customer.list(email: customer_email, limit: 1).data
    if customer_list.length == 1
      customer_list[0]
    else
      Stripe::Customer.create(email: customer_email)
    end
  rescue Stripe::StripeError => e
    log_info("Error creating or retrieving customer! #{e.message}")
    nil
  end
end

# This endpoint creates a PaymentIntent.
# https://stripe.com/docs/terminal/payments#create
#
# The example backend does not currently support connected accounts.
# To create a PaymentIntent for a connected account, see
# https://stripe.com/docs/terminal/features/connect#direct-payment-intents-server-side
post '/create_payment_intent' do
  log_info("=== create_payment_intent triggered — amount: #{params[:amount]}, currency: #{params[:currency] || 'usd'} ===")

  require_valid_api_key!

  # Validate required fields before hitting Stripe
  if params[:amount].nil? || params[:amount].to_s.strip.empty? || params[:amount].to_i <= 0
    status 400
    return { error: "'amount' is required and must be a positive integer (smallest currency unit, e.g. cents)" }.to_json
  end

  begin
    customer_email = params[:email] || params[:receipt_email]
    customer = lookup_or_create_customer(customer_email) if customer_email

    stripe_account_id = params[:stripe_account_id] || params['stripe_account_id']

    payment_intent_params = {
      payment_method_types: params[:payment_method_types] || ['card_present'],
      capture_method:       params[:capture_method] || 'manual',
      amount:               params[:amount].to_i,
      currency:             params[:currency] || 'usd',
      description:          params[:description] || 'Stripe Terminal Payment',
      receipt_email:        customer_email,
    }

    payment_intent_params[:customer] = customer.id if customer

    if params[:metadata] && !params[:metadata].empty?
      payment_intent_params[:metadata] = params[:metadata]
    end

    # Only forward payment_method_options when explicitly provided
    if params[:payment_method_options] && !params[:payment_method_options].empty?
      payment_intent_params[:payment_method_options] = params[:payment_method_options]
    end

    # Route funds to a connected Stripe account when provided
    if stripe_account_id && !stripe_account_id.strip.empty?
      payment_intent_params[:transfer_data] = { destination: stripe_account_id.strip }
      log_info("Stripe Connect: routing payment to connected account #{stripe_account_id}")
    end

    payment_intent = Stripe::PaymentIntent.create(payment_intent_params)
  rescue Stripe::StripeError => e
    log_info("Error creating PaymentIntent! #{e.message}")
    status stripe_error_status(e)
    return { error: e.message }.to_json
  end

  log_info("PaymentIntent successfully created: #{payment_intent.id}")
  status 200
  { intent: payment_intent.id, secret: payment_intent.client_secret }.to_json
end

# This endpoint captures a PaymentIntent.
# https://stripe.com/docs/terminal/payments#capture
post '/capture_payment_intent' do
  require_valid_api_key!
  id = params["payment_intent_id"] || params[:payment_intent_id]
  if id.nil? || id.to_s.strip.empty?
    status 400
    return { error: "'payment_intent_id' is required" }.to_json
  end

  begin
    if !params["amount_to_capture"].nil? && !params["amount_to_capture"].to_s.strip.empty?
      payment_intent = Stripe::PaymentIntent.capture(id, amount_to_capture: params["amount_to_capture"].to_i)
    else
      payment_intent = Stripe::PaymentIntent.capture(id)
    end
  rescue Stripe::StripeError => e
    log_info("Error capturing PaymentIntent! #{e.message}")
    status stripe_error_status(e)
    return { error: e.message }.to_json
  end

  log_info("PaymentIntent successfully captured: #{id}")
  status 200
  { intent: payment_intent.id, secret: payment_intent.client_secret }.to_json
end

# This endpoint cancels a PaymentIntent.
# https://stripe.com/docs/api/payment_intents/cancel
post '/cancel_payment_intent' do
  require_valid_api_key!
  id = params["payment_intent_id"] || params[:payment_intent_id]
  if id.nil? || id.to_s.strip.empty?
    status 400
    return { error: "'payment_intent_id' is required" }.to_json
  end

  begin
    payment_intent = Stripe::PaymentIntent.cancel(id)
  rescue Stripe::StripeError => e
    log_info("Error canceling PaymentIntent! #{e.message}")
    status stripe_error_status(e)
    return { error: e.message }.to_json
  end

  log_info("PaymentIntent successfully canceled: #{id}")
  status 200
  { intent: payment_intent.id, secret: payment_intent.client_secret }.to_json
end

# This endpoint creates a SetupIntent.
# https://stripe.com/docs/api/setup_intents/create
post '/create_setup_intent' do
  require_valid_api_key!

  begin
    setup_intent_params = {
      payment_method_types: params[:payment_method_types] || ['card_present'],
    }

    setup_intent_params[:customer]     = params[:customer]     unless params[:customer].nil?
    setup_intent_params[:description]  = params[:description]  unless params[:description].nil?
    setup_intent_params[:on_behalf_of] = params[:on_behalf_of] unless params[:on_behalf_of].nil?

    setup_intent = Stripe::SetupIntent.create(setup_intent_params)
  rescue Stripe::StripeError => e
    log_info("Error creating SetupIntent! #{e.message}")
    status stripe_error_status(e)
    return { error: e.message }.to_json
  end

  log_info("SetupIntent successfully created: #{setup_intent.id}")
  status 200
  { intent: setup_intent.id, secret: setup_intent.client_secret }.to_json
end

# Looks up or creates a Customer on your Stripe account with email "example@test.com".
# Used as a fallback when no customer_id or email is provided.
def lookup_or_create_example_customer
  example_email = "example@test.com"
  begin
    customer_list = Stripe::Customer.list(email: example_email, limit: 1).data
    if customer_list.length == 1
      customer_list[0]
    else
      Stripe::Customer.create(email: example_email)
    end
  rescue Stripe::StripeError => e
    log_info("Error creating or retrieving customer! #{e.message}")
    nil
  end
end

# This endpoint attaches a PaymentMethod to a Customer.
# https://stripe.com/docs/terminal/payments/saving-cards#read-reusable-card
# Accepts: payment_method_id (required), customer_id or email (optional; falls back to example customer)
post '/attach_payment_method_to_customer' do
  require_valid_api_key!
  pm_id = params[:payment_method_id] || params["payment_method_id"]
  if pm_id.nil? || pm_id.to_s.strip.empty?
    status 400
    return { error: "'payment_method_id' is required" }.to_json
  end

  begin
    customer = if params[:customer_id] && !params[:customer_id].to_s.strip.empty?
      Stripe::Customer.retrieve(params[:customer_id].to_s.strip)
    elsif params[:email] && !params[:email].to_s.strip.empty?
      lookup_or_create_customer(params[:email].to_s.strip)
    else
      lookup_or_create_example_customer
    end

    if customer.nil?
      status 400
      return { error: "Could not find or create a customer" }.to_json
    end

    payment_method = Stripe::PaymentMethod.attach(
      pm_id,
      {
        customer: customer.id,
        expand:   ["customer"],
      }
    )
  rescue Stripe::StripeError => e
    log_info("Error attaching PaymentMethod to Customer! #{e.message}")
    status stripe_error_status(e)
    return { error: e.message }.to_json
  end

  log_info("Attached PaymentMethod to Customer: #{customer.id}")
  status 200
  # Note that returning the Stripe payment_method object directly creates a dependency between your
  # backend's Stripe.api_version and your clients, making future upgrades more complicated.
  # All clients must also be ready for backwards-compatible changes at any time:
  # https://stripe.com/docs/upgrades#what-changes-does-stripe-consider-to-be-backwards-compatible
  payment_method.to_json
end

# This endpoint updates the PaymentIntent represented by 'payment_intent_id'.
# It currently only supports updating the 'receipt_email' property.
#
# https://stripe.com/docs/api/payment_intents/update
post '/update_payment_intent' do
  require_valid_api_key!

  payment_intent_id = params["payment_intent_id"] || params[:payment_intent_id]
  if payment_intent_id.nil? || payment_intent_id.to_s.strip.empty?
    status 400
    return { error: "'payment_intent_id' is a required parameter" }.to_json
  end

  begin
    allowed_keys = ["receipt_email"]
    update_params = params.select { |k, _| allowed_keys.include?(k) }

    payment_intent = Stripe::PaymentIntent.update(payment_intent_id, update_params)
    log_info("Updated PaymentIntent #{payment_intent_id}")
  rescue Stripe::StripeError => e
    log_info("Error updating PaymentIntent #{payment_intent_id}. #{e.message}")
    status stripe_error_status(e)
    return { error: e.message }.to_json
  end

  status 200
  { intent: payment_intent.id, secret: payment_intent.client_secret }.to_json
end

# This endpoint lists the first 100 Locations. If you will have more than 100
# Locations, you'll likely want to implement pagination in your application so that
# you can efficiently fetch Locations as needed.
# https://stripe.com/docs/api/terminal/locations
get '/list_locations' do
  require_valid_api_key!

  begin
    locations = Stripe::Terminal::Location.list(limit: 100)
  rescue Stripe::StripeError => e
    log_info("Error fetching Locations! #{e.message}")
    status stripe_error_status(e)
    return { error: e.message }.to_json
  end

  log_info("#{locations.data.size} Locations successfully fetched")
  status 200
  locations.data.to_json
end

# This endpoint creates a Location.
# https://stripe.com/docs/api/terminal/locations
post '/create_location' do
  require_valid_api_key!
  display_name = params[:display_name] || params["display_name"]
  if display_name.nil? || display_name.to_s.strip.empty?
    status 400
    return { error: "'display_name' is required to create a location. For more information, see https://stripe.com/docs/api/terminal/locations" }.to_json
  end

  begin
    location = Stripe::Terminal::Location.create(
      display_name: display_name.to_s.strip,
      address:      params[:address] || params["address"]
    )
  rescue Stripe::StripeError => e
    log_info("Error creating Location! #{e.message}")
    status stripe_error_status(e)
    return { error: e.message }.to_json
  end

  log_info("Location successfully created: #{location.id}")
  status 200
  location.to_json
end

# Global error handler: log unhandled exceptions and return a safe response.
error do
  err = env['sinatra.error']
  APP_LOGGER.error("#{err.class}: #{err.message}")
  APP_LOGGER.error(err.backtrace&.first(10)&.join("\n"))
  if PRODUCTION
    status 500
    { error: 'An unexpected error occurred. Please try again later.' }.to_json
  else
    raise err
  end
end

# Explicitly start the server when run directly (e.g. ruby web.rb).
# Required for Render/Heroku/Railway so the process binds to PORT and doesn't exit immediately.
if __FILE__ == $PROGRAM_NAME
  Sinatra::Application.run!(
    port: Sinatra::Application.settings.port,
    host: Sinatra::Application.settings.bind
  )
end
