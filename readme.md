# Card Wars Kingdom Reversed-Engineered Server

This is a reversed-engineered server for Card Wars Kingdom, designed for version 1.0.17 but it should also work with 1.19.1 available here: https://github.com/shishkabob27/CardWarsKingdom.

**Disclaimer**: This server is intended for use only by individuals you trust, as it lacks essential security measures in this version.

Blueprints are sourced from the original CWK and may require changes.

## Setup

1. **Server Configuration**: Navigate to `CardWarsKingdom/Card Wars Kingdom_data/StreamingAssets/server_settings.json` and replace the `server_url` with the web address of the server you want to connect to. You should also replace `photon_chat_app_id` and `photon_pun_app_id` if you intend to use PVP and Chat.

2. **VPN Usage**: It is recommended to use a VPN when connecting to someone else's server as your IP address will be logged.

## Running the Server

Make sure to install the required packages using `pip install -r requirements.txt`.

To run the server, simply run `python app.py`.
By default, the server will run on port 5000, however you can specify a different port by running `python app.py --port <port>`.

You can also use [Gunicorn](https://gunicorn.org/) to run the server with multiple workers.
Install Gunicorn using `pip install gunicorn` and run `gunicorn app:app` to start the server.
By default, Gunicorn will run on port 8000, however you can specify a different port by running `gunicorn app:app --bind 127.0.0.1:<port>`.

## Additional Setup

It is recommended to set up Chat and PUN servers with [Photon](https://www.photonengine.com/) if you want to play PVP and use chat exclusively with users of your server.
