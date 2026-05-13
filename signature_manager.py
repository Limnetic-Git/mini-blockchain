from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

class SignatureManager:
    @staticmethod
    def generate_keypair():
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key.private_bytes_raw().hex(), public_key.public_bytes_raw().hex()

    @staticmethod
    def sign(private_key_hex: str, message: bytes) -> bytes:
        private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
        return private_key.sign(message)

    @staticmethod
    def verify(public_key_hex: str, message: bytes, signature: bytes) -> bool:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        try:
            public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False
