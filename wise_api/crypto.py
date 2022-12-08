from base64 import b64encode

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


def generate_key_pair(bits: int = 2048) -> tuple[str, str]:
    private_key = RSA.generate(bits)
    public_key = private_key.public_key()

    return (
        private_key.export_key("PEM").decode("ascii"),
        public_key.export_key("PEM").decode("ascii"),
    )


def sign_approval_token(sign_key: str, token: str) -> str:
    signkey = RSA.import_key(sign_key)

    hashed_token = SHA256.new(token.encode("ascii"))
    signed_token = pkcs1_15.new(signkey).sign(hashed_token)
    signature = b64encode(signed_token).decode("ascii")

    return signature
