import base64, hashlib, json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def domain_message(domain, obj):
    return domain.encode("ascii") + b"\0" + canonical_bytes(obj)

def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()

def verify_ed25519(public_key_b64, signature_b64, domain, body):
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64, validate=True))
        sig = base64.b64decode(signature_b64, validate=True)
        key.verify(sig, domain_message(domain, body))
        return True
    except (ValueError, InvalidSignature):
        return False

def object_digest(domain, body):
    return sha256_hex(domain_message(domain, body))
