#!/usr/bin/env python3

"""
Conversion routines to/from Yubico modhex format.
https://developers.yubico.com/yubico-c/Manuals/modhex.1.html
"""

from binascii import a2b_hex, b2a_hex

# Modhex specification, copied & pasted from Yubico's website
# see https://developers.yubico.com/yubico-c/Manuals/modhex.1.html
MODHEX_SPEC="""0 1 2 3 4 5 6 7 8 9 a b c d e f
c b d e f g h i j k l n r t u v"""

# Forward and reverse mappings for Modhex
MODHEX_FWD_CONV=dict(zip(*MODHEX_SPEC.replace(' ','').split('\n')))
MODHEX_REV_CONV=dict([(v, k) for (k, v) in MODHEX_FWD_CONV.items()])

hex_to_modhex = lambda hexstr : ''.join([MODHEX_FWD_CONV[c] for c in hexstr])
hex_to_modhex.__doc__ = """Convert a hexadecimal string to modhex."""

modhex_to_hex = lambda modhexstr : ''.join([MODHEX_REV_CONV[c] for c in modhexstr])
modhex_to_hex.__doc__ = """Convert a modhex string to hexadecimal."""

a2b_modhex = lambda modhexstr : a2b_hex(modhex_to_hex(modhexstr))
a2b_modhex.__doc__ = """Convert a modhex string to bytes()."""

b2a_modhex = lambda binary : hex_to_modhex(b2a_hex(binary))
b2a_modhex.__doc__ = """Convert bytes() to a modhex string."""

__all__ = [ 'a2b_modhex', 'b2a_modhex', 'hex_to_modhex', 'modhex_to_hex' ]
