#!/usr/bin/env python3

from secrets import token_bytes
from typing import Any, Mapping

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


DEFAULT_KDF = 'scrypt'


class KDF(object):
    """
    Generic key-derivative function interface.
    """

    @classmethod
    def initialise(cls, key_len: int = 32, **kwargs):
        """
        Generate a new vault using this KDF implementation.
        """
        return NotImplementedError

    def derive(self, passphrase: bytes) -> bytes:
        """
        Derive a symmetric key secret from the passphrase using this KDF.
        """
        return NotImplementedError

    @property
    def settings(self) -> Mapping[str, Any]:
        """
        Dump the settings needed to restore this KDF function state from a
        file.
        """
        return NotImplementedError


_KDF = {}
def _register_kdf(kdf : type[KDF]):
    assert kdf.KDF_NAME not in _KDF, \
            'Duplicate KDF with name %s' % kdf.KDF_NAME
    _KDF[kdf.KDF_NAME] = kdf


def get_class(kdf_name: str) -> type[KDF]:
    """
    Return a KDF class by KDF name
    """
    return _KDF[kdf_name]


def init_kdf(kdf_name: str = DEFAULT_KDF, **kwargs) -> KDF:
    """
    Initialise a KDF with a new context.
    """
    kdf_class = get_class(kdf_name)
    config = kdf_class.KDF_DEFAULTS.copy()
    config.update(kwargs)
    kdf = kdf_class.initialise(**config)
    return kdf


def load_kdf(kdf_name: str, **kwargs) -> KDF:
    """
    Load a KDF from a saved context.
    """
    kdf_class = get_class(kdf_name)
    kdf = kdf_class(**kwargs)
    return kdf

__all__ = ['KDF', 'init_kdf', 'load_kdf']


class ScryptKDF(KDF):
    """
    A KDF based on the Scrypt algorithm
    """
    KDF_NAME = 'scrypt'
    KDF_DEFAULTS = dict(
            salt_len=32,
            n=2**20,
            r=8,
            p=1
    )

    @classmethod
    def initialise(cls,
            salt_len: int = 32,
            key_len: int = 32,
            n: int = 2**20,
            r: int = 8,
            p: int = 1,
            **kwargs):
        """
        Generate a new vault using this KDF implementation.
        """
        salt = token_bytes(salt_len)
        return cls(salt=salt, key_len=key_len, n=n, r=r, p=p, **kwargs)

    def __init__(self,
            salt: bytes,
            key_len: int = 32,
            n: int = 2**20,
            r: int = 8,
            p: int = 1,
            **kwargs
    ):
        self._params = dict(
                kdf_name=self.KDF_NAME, salt=salt,
                key_len=key_len, n=n, r=r, p=p
        )

    def derive(self, passphrase: bytes) -> bytes:
        return self._scrypt.derive(passphrase)

    @property
    def settings(self) -> Mapping[str, Any]:
        return self._params.copy()

    @property
    def _scrypt(self):
        params = self._params.copy()
        params.pop('kdf_name')
        key_len = params.pop('key_len')
        return Scrypt(**params, length=key_len)

_register_kdf(ScryptKDF)
