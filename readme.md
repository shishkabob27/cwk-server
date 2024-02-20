# Card Wars Kingdom Reversed-Engineered Server

This is a reversed-engineered server for Card Wars Kingdom, designed for version 1.0.17 available here: https://github.com/shishkabob27/CardWarsKingdom.

**Disclaimer**: This server is intended for use only by individuals you trust, as it lacks essential security measures in this version.

Blueprints are sourced from the original CWK and may require changes.

## Setup

1. **Server Configuration**: Navigate to `CardWarsKindom/Card Wars Kingdom_data/StreamingAssets/server_settings.json` and replace the `server_url` with the web address of the server you want to connect to. You should also replace `photon_chat_app_id` and `photon_pun_app_id` if you intend to use PVP and Chat.

2. **VPN Usage**: It is recommended to use a VPN when connecting to someone else's server.

## Running the Server

To run the server, use one of the following methods:

- Using Python: `python app.py`
- Using Gunicorn: `gunicorn app:app app.py`

## Additional Setup

It is recommended to set up Chat and PUN servers with [Photon](https://www.photonengine.com/) if you want to play PVP and use chat exclusively with users of your server.

## Questions and Support

For any issues or questions, please feel free to DM me on Discord, @shishkabob.org