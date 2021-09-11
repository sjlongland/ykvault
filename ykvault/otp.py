#!/usr/bin/env python3

"""
Yubikey OTP parser
"""

from typing import NamedTuple, Optional
from struct import Struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .modhex import a2b_modhex, b2a_modhex


# https://developers.yubico.com/OTP/OTPs_Explained.html
OTP_STRUCT = Struct('<6s16s')
TOKEN_STRUCT = Struct('<6sHHBBH')


class YubikeyToken(NamedTuple):
    """
    The Yubikey OTP token, sent encrypted with the device's AES-128 key.
    """
    private_uid: bytes
    usage_ctr: int
    timestamp: int
    session_ctr: int
    rnd: int

    @classmethod
    def parse(cls, token_cleartext : bytes):
        (
                private_uid,
                usage_ctr,
                timestamp_lo,
                timestamp_hi,
                session_ctr,
                rnd
        ) = TOKEN_STRUCT.unpack(token_cleartext[0:TOKEN_STRUCT.size])

        timestamp = (timestamp_hi << 16) | timestamp_lo

        return cls(
                private_uid=private_uid,
                usage_ctr=usage_ctr,
                timestamp=timestamp,
                session_ctr=session_ctr,
                rnd=rnd
        )


class YubikeyOTP(NamedTuple):
    """
    A Yubikey OTP, parsed out to its constituent parts.
    """
    public_uid: bytes
    token_ciphertext: bytes
    token: Optional[YubikeyToken]

    @classmethod
    def parse(cls, otp: str, key: Optional[bytes] = None):
        """
        Parse an OTP from a Yubikey.  If a key is given, decrypt the token.
        """

        (public_uid, token_ciphertext) = \
                OTP_STRUCT.unpack(a2b_modhex(otp))

        token: Optional[YubikeyToken] = None
        if key is not None:
            cipher = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
            token_cleartext: bytes = \
                    cipher.update(token_ciphertext) \
                    + cipher.finalize()

            token = YubikeyToken.parse(token_cleartext)

        return cls(
                public_uid=public_uid,
                token_ciphertext=token_ciphertext,
                token=token
        )
