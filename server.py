# server.py
import os
from flask import Flask, jsonify, redirect ,session ,request
from flask_cors import CORS  # Import CORS
from concord_logic.config import Config
from hushh_mcp import config as h_config
# Import the database tools we just created
from concord_logic.database import db_session, init_db
from concord_logic.database import User, Credential # Import the table models
from concord_logic.services.google_client import GoogleService
# --- Basic App Setup ---

# Temporarily comment out this import
# as encytpy from cyptography is not working but do this later as part of hacktahon
from hushh_mcp.vault.encrypt import encrypt_data

h_config.SECRET_KEY = Config.HUSHH_SECRET_KEY
h_config.VAULT_ENCRYPTION_KEY = Config.VAULT_ENCRYPTION_KEY

app = Flask(__name__)
app.config.from_object(Config)

# This is the CRITICAL part for allowing your React app to talk to this server.
# It tells the server to allow requests from 'http://localhost:3000'.
CORS(app, supports_credentials=True, origins=[Config.FRONTEND_URL])

init_db()
# --- Mock Data (The same data from your frontend's mockApi.js) ---

# This data will be replaced by real database calls later.
mock_user_status = {
  "isLoggedIn": True,
  "userId": "user_g_1122334455",
  "displayName": "Alice",
  "email": "alice@example.com",
  "avatarUrl": "https://i.pravatar.cc/150?u=alice",
  "googleConnected": True,
  "slackConnected": True # Change this to False to test the PermissionsWizard
}

mock_audit_log = [
  { "id": "evt_abc123", "timestamp": "2023-10-27T10:05:00Z", "event": "Scheduled Meeting", "details": "Booked 30min meeting with bob@example.com", "status": "Success" },
  { "id": "evt_def456", "timestamp": "2023-10-27T10:04:55Z", "event": "Agent Action", "details": "Requested to write to Google Calendar", "status": "Success" },
]


# Initialize the database by creating the .db file and tables
init_db()

# This function is crucial for cleaning up database connections.
@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()


# In server.py

@app.route("/api/user/status")
def get_user_status():
    print("--- Checking User Status ---")
    # Print the entire session object to see what's inside
    print(f"Session content on arrival: {session.items()}")

    if 'user_id' not in session:
        print("❌ User ID NOT found in session. Returning logged out.")
        return jsonify({"isLoggedIn": False})

    user = User.query.get(session['user_id'])
    if not user:
        print("❌ User ID was in session, but not found in DB. Clearing session.")
        session.clear()
        return jsonify({"isLoggedIn": False})

    print(f"✅ User ID {user.id} found in session and DB. Returning logged in.")
    # ... build and return the full JSON ...
    # (The rest of this function is the same)
    creds = Credential.query.filter_by(user_id=user.id).all()
    connected_services = {c.service_name for c in creds}
    return jsonify({
      "isLoggedIn": True,
      "userId": user.id,
      "displayName": user.display_name,
      "email": user.email,
      "avatarUrl": user.avatar_url,
      "googleConnected": "google_identity" in connected_services or "google_calendar" in connected_services,
      "slackConnected": "slack" in connected_services
    })


@app.route("/api/oauth-callback/google")
def oauth_callback_google():
    print("\n--- Google OAuth Callback Initiated ---")
    try:
        code = request.args.get('code')
        if not code:
            print("❌ ERROR: No 'code' provided in callback URL.")
            return "Error: Missing authorization code.", 400
        
        print("1. Authorization code received.")
        google_service = GoogleService()
        user_info, credentials_json = google_service.get_user_info_and_tokens(code)
        print(f"2. User info received from Google for: {user_info.get('email')}")

        vault_key = os.getenv("VAULT_ENCRYPTION_KEY")
        encrypted_payload = encrypt_data(credentials_json, key_hex=vault_key)
        print("3. Credentials successfully encrypted.")

        # Find or create the user in the database
        user = User.query.filter_by(google_id=user_info['sub']).first()
        if not user:
            print(f"4a. User not found. Creating new user...")
            user = User(
                google_id=user_info['sub'],
                display_name=user_info.get('name', 'Anonymous User'),
                email=user_info.get('email'),
                avatar_url=user_info.get('picture')
            )
            db_session.add(user)
            db_session.commit()
            print(f"4b. New user created with ID: {user.id}")
        else:
            print(f"4. User found in database with ID: {user.id}")

        # Find or create the credential
        identity_cred = Credential.query.filter_by(user_id=user.id, service_name='google_identity').first()
        if not identity_cred:
            print("5a. Identity credential not found. Creating new credential...")
            new_credential = Credential(
                user_id=user.id,
                service_name='google_identity',
                encrypted_token=str(encrypted_payload)
            )
            db_session.add(new_credential)
            db_session.commit()
            print("5b. New credential created and saved.")
        else:
            print("5. Identity credential already exists.")

        # THIS IS THE MOST IMPORTANT STEP
        session['user_id'] = user.id
        print(f"✅ 6. Session SET for user_id: {session['user_id']}")
        
        print("7. Redirecting to dashboard...")
        return redirect(f"{Config.FRONTEND_URL}/dashboard")

    except Exception as e:
        print(f"🔥🔥🔥 AN ERROR OCCURRED IN THE CALLBACK: {e}")
        # Also print the full traceback for detailed debugging
        import traceback
        traceback.print_exc()
        return "An internal error occurred during authentication.", 500



# @app.route("/api/user/status")
# def get_user_status():
#     """
#     This function no longer uses mock data.
#     It checks the user's session and queries the real database.
#     """
#     print("✅ API HIT: /api/user/status (REAL)")

#     # Check if we have a user_id stored in the session cookie
#     if 'user_id' not in session:
#         return jsonify({"isLoggedIn": False})

#     # Find the user in the database
#     user = User.query.get(session['user_id'])
#     if not user:
#         # If the user in the session doesn't exist in the DB, clear the session
#         session.clear()
#         return jsonify({"isLoggedIn": False})

#     # Check which credentials the user has connected
#     creds = Credential.query.filter_by(user_id=user.id).all()
#     connected_services = {c.service_name for c in creds}

#     # Build the real response from live database data
#     return jsonify({
#       "isLoggedIn": True,
#       "userId": user.id,
#       "displayName": user.display_name,
#       "email": user.email,
#       "avatarUrl": user.avatar_url,
#       "googleConnected": "google_calendar" in connected_services,
#       "slackConnected": "slack" in connected_services
#     })


@app.route("/api/auth/login/google")
def login_google():
    """ Kicks off the Google Login flow by redirecting to Google. """
    google_service = GoogleService()
    auth_url = google_service.get_auth_url()
    return redirect(auth_url)


# @app.route("/api/oauth-callback/google")
# def oauth_callback_google():
#     """ Handles the response from Google after user gives consent. """
#     code = request.args.get('code')
#     google_service = GoogleService()
#     user_info, credentials_json = google_service.get_user_info_and_tokens(code)
    
#     vault_key = os.getenv("VAULT_ENCRYPTION_KEY")
#     encrypted_payload = encrypt_data(credentials_json, key_hex=vault_key)
    
#     user = User.query.filter_by(google_id=user_info['sub']).first()

#     if not user:
#         user = User(
#             google_id=user_info['sub'],
#             display_name=user_info.get('name', 'Anonymous User'),
#             email=user_info.get('email'),
#             avatar_url=user_info.get('picture')
#         )
#         db_session.add(user)
#         db_session.commit()

#         # --- THIS IS THE LINE TO FIX ---
#         # Before: encrypted_token=encrypted_payload.decode('utf-8') (This was wrong)
#         # After: We convert the entire EncryptedPayload object to a string.
#         new_credential = Credential(
#             user_id=user.id,
#             service_name='google_identity',
#             encrypted_token=str(encrypted_payload) # <-- THE FIX IS HERE
#         )
#         # -------------------------------

#         db_session.add(new_credential)
#         db_session.commit()
    
#     session['user_id'] = user.id
#     print(f"✅ Session set for user_id: {session['user_id']}")
#     return redirect("http://localhost:3000/dashboard")

# === Dashboard & Data ===

@app.route("/api/user/audit-log")
def get_audit_log():
    
    print("API HIT: /api/user/audit-log")
    return jsonify(mock_audit_log)

# === Action & Control ===

@app.route("/api/logout", methods=["POST"])
def logout():
    print("API HIT: /api/logout")
    return jsonify({"status": "ok", "message": "Logged out"})

@app.route("/api/revoke/google", methods=["POST"])
def revoke_google():
    """ NEW: Handles revoking Google connection. """
    print("API HIT: /api/revoke/google")
    return jsonify({"status": "ok", "message": "Google connection revoked"})

@app.route("/api/revoke/slack", methods=["POST"])
def revoke_slack():
    """ NEW: Handles revoking Slack connection. """
    print("API HIT: /api/revoke/slack")
    return jsonify({"status": "ok", "message": "Slack connection revoked"})

@app.route("/api/revoke/all", methods=["POST"])
def revoke_all():
    """ NEW: Handles revoking all user data. """
    print("API HIT: /api/revoke/all")
    return jsonify({"status": "ok", "message": "All data revoked"})

# === Slack Webhook (Not for frontend) ===
@app.route("/api/slack/command", methods=["POST"])
def slack_command():
    # ... This is for the Agent Specialist ...
    return "OK", 200


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)