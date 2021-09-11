#!/usr/bin/env python3

from typing import NamedTuple
from secrets import token_bytes

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


class CBCCipherText(NamedTuple):
    iv: bytes
    ciphertext: bytes


def load(key: bytes, ciphertext: CBCCipherText) -> bytes:
    """
    Decrypt and load the ciphertext given.
    """
    cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(ciphertext.iv)
    ).decryptor()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(
            cipher.update(ciphertext.ciphertext)
            + cipher.finalize()
    ) + unpadder.finalize()


def dump(key: bytes, data: bytes) -> CBCCipherText:
    """
    Encrypt the given payload with the given key and return the IV and
    ciphertext.
    """
    iv = token_bytes(16)
    cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv)
    ).encryptor()

    padder = padding.PKCS7(128).padder()

    return CBCCipherText(
            iv=iv,
            ciphertext=cipher.update(
                padder.update(data)
                + padder.finalize()
            ) + cipher.finalize()
    )
