from flask import Flask, request, redirect, session
import requests
import secrets, base64, hashlib
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

client_id = os.getenv(CLIENT_ID)
redirect_uri = "http://127.0.0.0:5555/callback"
scope = "user-read-currently-playing"

@app.route('/')
def index():
  code = request.args.get('code')
  if not code:
    return redirect_to_auth_code_flow(client_id)
  else:
    access_token = get_access_token(client_id, code)
    profile = fetch_profile(access_token)
    print(profile)
    return profile
    # return populate_ui(profile)

def redirect_to_auth_code_flow(client_id):
  verifier = generate_code_verifier(128)
  challenge = generate_code_challenge(verifier)

  session['verifier'] = verifier

  params = {
    "client_id": client_id,
    "response_type": "code",
    "redirect_uri": redirect_uri,
    "scope": scope,
    "code_challenge_method": "S256",
    "code_challenge": challenge
  }

  auth_url = "https://accounts.spotify.com/authorize?" + "&".join([f"{key}={value}" for key, value in params.items()])
  return redirect(auth_url)

def generate_code_verifier(length):
  return secrets.token_urlsafe(length)[:length]

def generate_code_challenge(verifier):
  digest = hashlib.sha256(verifier.encode()).digest()
  return base64.urlsafe_b64encode(digest).decode().replace('=', '')

def get_access_token(client_id, code):
  verifier = session.get('verifier')

  params = {
    "client_id": client_id,
    "grant_type": "authorization_code",
    "code": code,
    "redirect_uri": redirect_uri,
    "code_verifier": verifier
  }

  headers = {"Content-Type": "application/x-www-form-urlencoded"}
  response = requests.post("https://accounts.spotify.com/api/token", data=params, headers=headers)
  response_data = response.json()
  return response_data['access_token']

def fetch_profile(token):
  headers = {"Authorization": f"Bearer {token}"}
  response = requests.get("https://api.spotify.com/v1/me/player/currently-playing", headers=headers)
  return response.json()

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=5555, debug=True)