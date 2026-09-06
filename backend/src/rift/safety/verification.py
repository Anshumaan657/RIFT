"""HTTP challenge verification through the controlled client."""

import hashlib
import hmac

from rift.safety.http_client import SafeHttpClient


def challenge_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def verify_http_challenge(client: SafeHttpClient, token_digest: str) -> bool:
    base = client.target.base_path
    challenge_path = f"{base.rstrip('/')}/.well-known/rift-challenge.txt"
    response = await client.request("GET", challenge_path)
    if response.status_code != 200:
        return False
    observed = hashlib.sha256(response.body.strip()).hexdigest()
    return hmac.compare_digest(observed, token_digest)
