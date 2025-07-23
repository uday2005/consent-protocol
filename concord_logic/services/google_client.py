# concord_logic/services/google_client.py
import os
from dotenv import load_dotenv
import google.oauth2.credentials
import google_auth_oauthlib.flow
import requests
from concord_logic.config import Config
# Load the environment variables from your .env file
load_dotenv()

class GoogleService:
    def __init__(self):
        # This dictionary is the configuration that Google's library needs.
        # It is built directly from your .env file.
        self.client_config = {
            "web": {
                "client_id": Config.GOOGLE_CLIENT_ID,
                "client_secret": Config.GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://accounts.google.com/o/oauth2/token",
            }
        }

        self.redirect_uri = Config.GOOGLE_REDIRECT_URI
        
        # This tells Google we want to know the user's identity
        self.scopes = [
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email",
            "openid"
        ]

    def get_auth_url(self):
        # Create a Flow instance directly from our configuration dictionary.
        # It does NOT use from_client_secrets_file.
        flow = google_auth_oauthlib.flow.Flow.from_client_config(
            self.client_config,
            scopes=self.scopes,
            redirect_uri=self.redirect_uri
        )
        
        # Generate the URL the user will be sent to
        auth_url, _ = flow.authorization_url(access_type='offline', prompt='consent')
        return auth_url

    def get_user_info_and_tokens(self, code):
        # Create a new flow instance to exchange the code for tokens
        flow = google_auth_oauthlib.flow.Flow.from_client_config(
            self.client_config,
            scopes=self.scopes,
            redirect_uri=self.redirect_uri
        )
        
        # This is the step that talks to Google to get the tokens
        flow.fetch_token(code=code)
        
        credentials = flow.credentials
        
        # Use the token to get the user's profile information
        user_info_response = requests.get(
            'https://www.googleapis.com/oauth2/v3/userinfo',
            headers={'Authorization': f'Bearer {credentials.token}'}
        )
        user_info = user_info_response.json()

        # Return both the user's info and their tokens (as a JSON string)
        return user_info, credentials.to_json()