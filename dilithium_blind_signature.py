import hashlib
import json
from typing import Dict, Tuple
from secrets import randbelow
from pqcrypto.sign import dilithium3
from cryptography.hazmat.primitives import constant_time


class DilithiumBlindSignature:
    """
    A class for handling Dilithium blind signature operations.
    """

    @staticmethod
    def hash_message(message: str) -> bytes:
        with hashlib.blake2s() as hasher:
            hasher.update(message.encode('utf-8'))
            return hasher.digest()

    @staticmethod
    def int_to_bytes(value: int, byteorder='big') -> bytes:
        return value.to_bytes(32, byteorder)

    @staticmethod
    def bytes_to_int(value: bytes, byteorder='big') -> int:
        return int.from_bytes(value, byteorder)

    @staticmethod
    def blind(message: str, blinding_factor: int) -> bytes:
        message_hash_int = DilithiumBlindSignature.bytes_to_int(
            DilithiumBlindSignature.hash_message(message))
        blinded_message = (message_hash_int * blinding_factor) % (2 ** 256)
        return DilithiumBlindSignature.int_to_bytes(blinded_message)

    @staticmethod
    def unblind(signed_blinded_message: bytes, blinding_factor_inv: int) -> bytes:
        signed_message_int = (DilithiumBlindSignature.bytes_to_int(
            signed_blinded_message) * blinding_factor_inv) % (2 ** 256)
        return DilithiumBlindSignature.int_to_bytes(signed_message_int)

    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        return dilithium3.generate_keypair()

    @staticmethod
    def sign(secret_key: bytes, message: bytes) -> bytes:
        return dilithium3.sign(secret_key, message)

    @staticmethod
    def verify(public_key: bytes, signature: bytes, message: str) -> bool:
        message_hash = DilithiumBlindSignature.hash_message(message)
        try:
            expected_signature = dilithium3.sign(public_key, message_hash)
            return constant_time.bytes_eq(signature, expected_signature)
        except ValueError:
            return False

    @staticmethod
    def generate_blinding_factor() -> Tuple[int, int]:
        max_value = 2 ** 256
        blinding_factor = randbelow(max_value)
        while True:
            try:
                blinding_factor_inv = pow(blinding_factor, -1, max_value)
                break
            except ValueError:
                blinding_factor = randbelow(max_value)
        return blinding_factor, blinding_factor_inv


class DigitalPayment:
    def create_payment_request(self, payer_public_key: bytes, amount: float, payment_id: str) -> Dict[str, str]:
        if amount < 0:
            raise ValueError("Payment amount cannot be negative")

        payment_request = {
            "payer_public_key": payer_public_key.hex(),
            "amount": str(amount),
            "payment_id": payment_id
        }
        return payment_request

    def sign_payment_request(self, payment_request: Dict[str, str], secret_key: bytes) -> str:
        payment_request_json = json.dumps(payment_request, sort_keys=True)
        signature = DilithiumBlindSignature.sign(
            secret_key, payment_request_json.encode('utf-8'))
        return signature.hex()

    def verify_payment_request(self, payment_request: Dict[str, str], signature: str, public_key: bytes) -> bool:
        payment_request_json = json.dumps(payment_request, sort_keys=True)
        signature_bytes = bytes.fromhex(signature)
        return DilithiumBlindSignature.verify(public_key, signature_bytes, payment_request_json)
