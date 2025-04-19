import base64
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Load the private key
with open('jwttool_custom_private_RSA.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )

# Get the public key components
public_numbers = private_key.public_key().public_numbers()

# Convert to base64url encoding (required for JWK)
def int_to_base64url(value):
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

# Extract n and e values in base64url format
n = int_to_base64url(public_numbers.n)
e = int_to_base64url(public_numbers.e)

# Generate a simple key ID (you can make this whatever you want)
kid = "jwt_tool"  # Simple example

# Create JWK
jwk = {
    "kty": "RSA",
    "kid": kid,
    "use": "sig",
    "alg": "RS256",
    "n": n,
    "e": e
}

print(json.dumps(jwk, indent=2))

# Create the full JWK Set
jwk_set = {
    "keys": [jwk]
}

# Save to file
with open('jwks.json', 'w') as f:
    json.dump(jwk_set, f, indent=2)