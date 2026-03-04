# Rack config for Puma (recommended on Render/Heroku).
# Start with: bundle exec puma -p $PORT -e production config.ru
require './web'
run Sinatra::Application
