#!/usr/bin/env python3

"""
Yubikey OTP parser
"""

from typing import NamedTuple, Optional
from struct import Struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .modhex import a2b_modhex, b2a_modhex
from .crc import yubikey_crc16


# https://developers.yubico.com/OTP/OTPs_Explained.html
OTP_STRUCT = Struct('<6s16s')
TOKEN_STRUCT = Struct('<6sHHBBHH')


class YubikeyToken(NamedTuple):
    """
    The Yubikey OTP token, sent encrypted with the device's AES-128 key.
    """
    private_uid: bytes
    usage_ctr: int
    timestamp: int
    session_ctr: int
    rnd: int
    crc: int

    @classmethod
    def parse(cls, token_cleartext : bytes):
        """
        Parse a Yubico OTP token field.

        Assumes the field has been previously decrypted using a key matching
        the AES-128 key stored in the Yubikey.  Raises ValueError if the CRC
        is found to be incorrect, suggesting a forged OTP.
        """
        (
                private_uid,
                usage_ctr,
                timestamp_lo,
                timestamp_hi,
                session_ctr,
                rnd,
                crc
        ) = TOKEN_STRUCT.unpack(token_cleartext[0:TOKEN_STRUCT.size])

        # Validate CRC: The checksum is verified by calculating the
        # checksum of all bytes, including the checksum field.  This
        # shall give a fixed residual of 0xf0b8 if the checksum is valid.
        # If the checksum is invalid, the OTP shall be rejected.
        computed_crc: int = yubikey_crc16(token_cleartext)
        if computed_crc != 0xf0b8:
            raise ValueError('Bad CRC, got 0x%04x' % computed_crc)

        timestamp = (timestamp_hi << 16) | timestamp_lo

        return cls(
                private_uid=private_uid,
                usage_ctr=usage_ctr,
                timestamp=timestamp,
                session_ctr=session_ctr,
                rnd=rnd,
                crc=crc
        )


class YubikeyOTP(NamedTuple):
    """
    A Yubikey OTP, parsed out to its constituent parts.
    """
    public_uid: bytes
    token_ciphertext: bytes
    token_cleartext: Optional[bytes]
    token: Optional[YubikeyToken]

    @classmethod
    def parse(cls, otp: str, key: Optional[bytes] = None):
        """
        Parse an OTP from a Yubikey.  If a key is given, decrypt the token.
        """

        (public_uid, token_ciphertext) = \
                OTP_STRUCT.unpack(a2b_modhex(otp))

        otp = cls(
                public_uid=public_uid,
                token_ciphertext=token_ciphertext,
                token_cleartext=None,
                token=None
        )

        if key is not None:
            return otp.decode(key)
        else:
            return otp

    def decode(self, key: bytes):
        cipher = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        token_cleartext: bytes = \
                cipher.update(self.token_ciphertext) \
                + cipher.finalize()

        token: YubikeyToken = YubikeyToken.parse(token_cleartext)
        return self.__class__(
                public_uid=self.public_uid,
                token_ciphertext=self.token_ciphertext,
                token_cleartext=token_cleartext,
                token=token
        )
