import os
import time
import json
import base64
import logging
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import jwt  # PyJWT

def generate_jwt(api_key: str, api_secret_b64: str) -> str:
    decoded = base64.b64decode(api_secret_b64)
    private_key = Ed25519PrivateKey.from_private_bytes(decoded[:32])
    now = int(time.time())
    payload = {
        "iss": api_key,
        "sub": api_key,
        "iat": now,
        "exp": now + 300,
        "nbf": now
    }
    token = jwt.encode(payload, private_key, algorithm="EdDSA", headers={
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": api_key
    })
    return token

def fetch_account_data(jwt_token: str):
    url = "https://api.coinbase.com/api/v3/brokerage/accounts"
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Content-Type": "application/json"
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def main():
    logging.basicConfig(level=logging.INFO)
    api_key = os.environ["COINBASE_API_KEY"]
    api_secret = os.environ["COINBASE_API_SECRET"]
    jwt_token = generate_jwt(api_key, api_secret)
    logging.info("✅ JWT generated")
    data = fetch_account_data(jwt_token)
    print(json.dumps(data, indent=2))

if __name__ == "__main__":
    main()
