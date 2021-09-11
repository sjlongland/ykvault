#!/usr/bin/env python3

from typing import Optional, Mapping, MutableMapping, NamedTuple

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

import cbor
import hashlib
import os
import os.path
from secrets import token_bytes

from .otp import YubikeyOTP
from .kdf import KDF, init_kdf, load_kdf
from .cipher import CBCCipherText, load, dump


def combine_keys(k1: bytes, k2: bytes) -> bytes:
    """
    Combine two keys together, producing a "composite" key.
    """
    k1_hash = hashlib.sha3_512(k1).digest()
    k2_hash = hashlib.sha3_512(k2).digest()

    return bytes([
        a ^ b
        for (a, b)
        in zip(k1_hash, k2_hash)
    ])


class YKVault(object):
    """
    An implementation of a "vault" using a YubiKey hardware token
    as the second factor.
    """

    def __init__(self, statefile: str, **kwargs):
        self._statefile = statefile
        self._kdf_defaults = kwargs
        self._state: Optional[MutableMapping[bytes, YKContext]] = None
        self._vault_cipher: Optional[Cipher] = None
        self._vault_kdf: Optional[KDF] = None

    def init(self, passphrase: str, **kwargs):
        """
        Initialise a new vault, blowing away any existing content.
        """
        # Initialise the KDF
        self._vault_kdf = init_kdf(**self._kdf_defaults)

        # Set up an empty state
        self._state = {}
        self.save(passphrase)

    def unseal(self, passphrase: str):
        """
        Unseal the vault with the given passphrase.
        """
        if self._state is not None:
            return

        with open(self._statefile, 'rb') as statefile:
            statedata = cbor.loads(statefile.read())

        # Pick out the KDF settings used for the vault
        self._vault_kdf = load_kdf(**statedata['vault'])

        # Derive the key used to seal the vault data
        self._seal_key = self._vault_kdf.derive(passphrase.encode('UTF-8'))

        # Now try to load the vault data
        raw_data = load(
                key=self._seal_key,
                ciphertext=CBCCipherText(
                    iv=statedata['iv'],
                    ciphertext=statedata['data']
                )
        )

        data = cbor.loads(raw_data)
        state: MutableMapping[bytes, YKContext] = {}
        for (public_uid, context) in data.items():
            state[public_uid] = YKContext.load(context)

        self._state = state

    def seal(self, new_passphrase: Optional[str] = None):
        """
        Seal the vault.
        """
        self.save(new_passphrase)
        self._seal_key = None
        self._state = None

    def save(self, new_passphrase: Optional[str] = None):
        """
        Save the state of the vault, optionally with a new passphrase.
        """
        if new_passphrase is not None:
            seal_key = self._vault_kdf.derive(new_passphrase.encode('UTF-8'))
        else:
            seal_key = self._seal_key

        # Gather the state
        context_data = cbor.dumps(dict([
            (public_uid, context.state)
            for (public_uid, context)
            in self._state.items()
        ]))

        # Encrypt the state
        sealed_data = dump(
                key=seal_key,
                data=context_data
        )

        # Encapsulate the payload
        payload = cbor.dumps(dict(
            vault=self._vault_kdf.settings,
            iv=sealed_data.iv,
            data=sealed_data.ciphertext
        ))

        # Back up the existing state file
        backup = self._statefile + '.bkp'
        if os.path.exists(backup):
            os.unlink(backup)
        if os.path.exists(self._statefile):
            os.rename(self._statefile, backup)

        # Write out the new state
        with open(self._statefile, 'wb') as statefile:
            statefile.write(payload)

        # Record the key used to seal the vault.
        self._seal_key = seal_key

        # Blow away back-up if successful
        if os.path.exists(backup):
            os.unlink(backup)

    def generate_secret(self,
            passphrase: str, otpstring: str, key: bytes,
            **kwargs
    ):
        """
        Generate a new secret and store it in the vault.
        """
        assert self._state is not None, 'Unseal the vault first'
        otp = YubikeyOTP.parse(otpstring, key)

        kdf_config = self._vault_kdf.settings.copy()
        kdf_config.update(**kwargs)

        assert otp.public_uid not in self._state, \
                'This YubiKey is already in use'
        self._state[otp.public_uid] = YKContext.init(
                key=key, passphrase=passphrase, otp=otp,
                **kdf_config
        )

    def get_secret(self, passphrase: str, otpstring: str) -> bytes:
        """
        Validate the passphrase and OTP, then derive a symmetric key secret.
        """
        assert self._state is not None, 'Unseal the vault first'

        otp = YubikeyOTP.parse(otpstring)
        context = self._state[otp.public_uid]
        return context.get_secret(passphrase, otp)


class YKSecretContext(NamedTuple):
    usage_ctr: int
    session_ctr: int

    @classmethod
    def load(cls, key: bytes, ciphertext: CBCCipherText):
        cleartext = load(key, ciphertext)
        data = cbor.loads(cleartext)
        return cls(**data)

    def dump(self, key: bytes) -> CBCCipherText:
        return dump(
                key=key,
                data=cbor.dumps(
                    dict(
                        usage_ctr=self.usage_ctr,
                        session_ctr=self.session_ctr
                    )
                )
        )


class YKContext(object):
    """
    A YubiKey Context stored within the vault.
    """
    @classmethod
    def load(cls, context: Mapping[str, bytes]):
        return cls(
                key=context['key'],
                iv=context['iv'],
                context=context['context']
        )

    @classmethod
    def init(cls, key: bytes, passphrase: str, otp: YubikeyOTP, **kwargs):
        """
        Create a new YubiKey context from the given key, passphrase
        and OTP.
        """
        # Initialise with a dummy context for now
        context = cls(key=key, iv=b'', context=b'', **kwargs)

        # Derive the key used for the shared context
        context_key = context._derive_key(passphrase, otp)

        # Save the new context and return it.
        context._update_context(context_key, otp)
        return context


    def __init__(self,
            key: bytes,
            iv: bytes,
            context: bytes,
            **kwargs
    ):
        self._key = key
        self._context = CBCCipherText(
                iv=iv, ciphertext=context
        )
        self._context_kdf = load_kdf(**kwargs)

    @property
    def state(self) -> Mapping[str, bytes]:
        """
        Dump the state of the context for persistance purposes.
        """
        return dict(
                key=self._key,
                iv=self._context.iv,
                context=self._context.ciphertext
        )

    def get_secret(self, passphrase: str, encrypted_otp: YubikeyOTP):
        """
        Derive the secret used with this YubiKey context.
        """
        # Decrypt the YubiKey token
        otp = encrypted_otp.decode(self._key)

        # Derive the key used for the shared context
        context_key = self._derive_key(passphrase, otp)

        context = YKSecretContext.load(
                key=context_key, ciphertext=self._context
        )

        # Validate the token is not a repeat
        if ( \
            (context.usage_ctr == otp.token.usage_ctr) \
            and (context.session_ctr >= otp.token.session_ctr) \
        ) or (context.usage_ctr > otp.token.usage_ctr):
            raise ValueError('OTP is replayed')

        # We're good… create a new context state and save it
        self._update_context(context_key, otp)

        # Return the derived secret
        return context_key

    def _derive_key(self, passphrase: str, otp: YubikeyOTP) -> bytes:
        """
        Derive a symmetric AES key from the YubiKey private UID and
        the user's passphrase.
        """
        return self._context_kdf.derive(
                combine_keys(
                    passphrase.encode('utf-8'),
                    otp.token.private_uid
                )
        )

    def _update_context(self, context_key: bytes, otp: YubikeyOTP):
        """
        Write a new context with the given OTP and key.
        """
        context = YKSecretContext(
                session_ctr=otp.token.session_ctr,
                usage_ctr=otp.token.usage_ctr
        )
        self._context = context.dump(context_key)
