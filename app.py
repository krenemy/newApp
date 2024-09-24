from flask import Flask, redirect, url_for, session, request
import google.auth.transport.requests
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import os
import base64
from dotenv import load_dotenv
from openai import OpenAI  # Version 1.33.0
from openai.types.beta.threads.message_create_params import Attachment, AttachmentToolFileSearch
import json
from PIL import Image
import pytesseract
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app = Flask(__name__)
load_dotenv()
app.secret_key = os.getenv('SECRET_KEY')
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
@app.route('/')
def index():
    return f'''
        <div class="">
            <h1>Welcome!</h1>
            <p><a href="/login">Login with Google</a></p>
        </div>
    '''

@app.route('/login')
def login():
    # Start the OAuth 2.0 flow
    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        {
            "installed": {
                "client_id": os.getenv('CLIENT_ID'),
                "project_id": os.getenv('PROJECT_ID'),
                "auth_uri": os.getenv('AUTH_URI'),
                "token_uri": os.getenv('TOKEN_URI'),
                "auth_provider_x509_cert_url": os.getenv('AUTH_PROVIDER_X509_CERT_URL'),
                "client_secret": os.getenv('GOOGLE_CLIENT_SECRET'),
                "redirect_uris": [os.getenv('REDIRECT_URIS')]
            }
        },
        scopes=SCOPES
    )
    
    # Redirect URI (must match the one in Google Cloud Console)
    flow.redirect_uri = url_for('callback', _external=True)

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true')
    
    # Store the state in the session to verify it later
    session['state'] = state

    return redirect(authorization_url)

@app.route('/callback')
def callback():
    # Verify the state to prevent CSRF attacks
    state = session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        {
            "installed": {
                "client_id": os.getenv('CLIENT_ID'),
                "project_id": os.getenv('PROJECT_ID'),
                "auth_uri": os.getenv('AUTH_URI'),
                "token_uri": os.getenv('TOKEN_URI'),
                "auth_provider_x509_cert_url": os.getenv('AUTH_PROVIDER_X509_CERT_URL'),
                "client_secret": os.getenv('GOOGLE_CLIENT_SECRET'),
                "redirect_uris": [os.getenv('REDIRECT_URIS')]
            }
        },
        scopes=SCOPES
    )
    flow.redirect_uri = url_for('callback', _external=True)
    print(flow.redirect_uri)
    # Exchange the authorization code for credentials
    authorization_response = request.url
    print('fetching token')
    flow.fetch_token(authorization_response=authorization_response)
    print("token fetched")
    # Save the credentials in session
    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

    return redirect(url_for('gmail'))
    # Check if the user is authenticated
    if 'credentials' not in session:
        return redirect('login')

    # Load credentials from the session
    credentials = google.oauth2.credentials.Credentials(
        **session['credentials'])

    # Build the Gmail API service

    gmail_service = googleapiclient.discovery.build(
        'gmail', 'v1', credentials=credentials)
    results = gmail_service.users().messages().list(userId='me', maxResults=30).execute()
    messages = results.get('messages', [])
    return ''.join()

@app.route('/gmail')
def gmail():
    # Check if the user is authenticated
    if 'credentials' not in session:
        return redirect('login')

    # Load credentials from the session
    credentials = google.oauth2.credentials.Credentials(
        **session['credentials'])

    # Build the Gmail API service
    gmail_service = googleapiclient.discovery.build(
        'gmail', 'v1', credentials=credentials)

    # Fetch the messages
    results = gmail_service.users().messages().list(userId='me', maxResults=30).execute()
    messages = results.get('messages', [])

    # If there are no messages
    if not messages:
        return '<h2>No messages found.</h2>'

    # Prepare the list of messages to display
    message_list = []
    for message in messages:
        msg = gmail_service.users().messages().get(userId='me', id=message['id']).execute()
        message_list.append(f"Message ID: {msg['id']}<br>Snippet: {msg.get('snippet', 'No snippet available')}<br><br>")

    return ''.join(message_list)
if __name__ == '__main__':
    app.run(os.getenv('HOST'),os.getenv('PORT'))



