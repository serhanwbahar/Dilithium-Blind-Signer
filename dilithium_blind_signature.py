import hashlib
from typing import Tuple
from secrets import randbits
from pqcrypto.sign import dilithium3
from cryptography.hazmat.primitives import constant_time


class DilithiumBlindSignature:
    """
    A class for handling Dilithium blind signature operations.
    """

    _hasher = hashlib.blake2s()

    @staticmethod
    def hash_message(message: str) -> bytes:
        """
        Hash the given message using BLAKE2s.
        """
        hasher = DilithiumBlindSignature._hasher.copy()
        hasher.update(message.encode('utf-8'))
        return hasher.digest()

    @staticmethod
    def blind(message: str, blinding_factor: int) -> bytes:
        """
        Blind the given message using the provided blinding factor.
        """
        message_hash_int = int.from_bytes(
            DilithiumBlindSignature.hash_message(message), byteorder='big')
        blinded_message = (message_hash_int * blinding_factor) % (2 ** 256)
        return blinded_message.to_bytes(32, byteorder='big')

    @staticmethod
    def unblind(signed_blinded_message: bytes, blinding_factor_inv: int) -> bytes:
        """
        Unblind the given signed and blinded message using the provided inverse blinding factor.
        """
        signed_message_int = (int.from_bytes(
            signed_blinded_message, byteorder='big') * blinding_factor_inv) % (2 ** 256)
        return signed_message_int.to_bytes(32, byteorder='big')

    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        """
        Generate a Dilithium key pair.
        """
        return dilithium3.generate_keypair()

    @staticmethod
    def sign(secret_key: bytes, message: bytes) -> bytes:
        """
        Sign the given message using the provided secret key.
        """
        return dilithium3.sign(secret_key, message)

    @staticmethod
    def verify(public_key: bytes, signature: bytes, message: str) -> bool:
        """
        Verify the given signature for the provided message using the public key.
        """
        message_hash = DilithiumBlindSignature.hash_message(message)
        try:
            dilithium3.verify(public_key, signature, message_hash)
            return True
        except ValueError:
            return False

    @staticmethod
    def generate_blinding_factor() -> Tuple[int, int]:
        """
        Generate a cryptographically secure blinding factor and its inverse.
        """
        blinding_factor = randbits(256)
        blinding_factor_inv = pow(blinding_factor, -1, 2 ** 256)
        return blinding_factor, blinding_factor_inv
