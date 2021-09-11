# Proof-of-concept YubiKey-backed vault

This is a proof-of-concept vault designed to use a YubiKey in OTP mode as the
second factor in a 2FA vault.

## Why do this?

Many years ago… back in 2011, I attended the `linux.conf.au` conference in
Brisbane, and as part of my admission, I was given a YubiKey free.  I mucked
around with it for a bit, did an experimental `pam` module that worked offline,
but otherwise, didn't have a lot of use for it until I started using it with my
workplace Vultr and LastPass accounts.

Fast forward to a few weeks back, we needed 2FA on AWS, which do not support
the older YubiKeys.  So work bought fancy new U2F-capable (YubiKey 5 series)
ones, and this pre-U2F key has been made redundant ever since.  I wanted to
experiment with other ways this could be used.

## How does this work

This relies on knowing the 128-bit AES key stored in the YubiKey.  Yubico
normally program the keys with a unique AES key, but don't share with the
customer what that secret was.  They _do_, however, provide a tool that can
program in a new custom key, and a site where you can post the new secret to in
the event you still want to use the key online after reprogramming.

So, if you reprogram the key yourself, you can store that secret somewhere, and
you have the ability to use the YubiKey offline.  A lone symmetric key though
isn't that useful, you need to store that key securely (otherwise anyone who
gets hold of it can spoof your key!).  You _could_ use that key to also encrypt
your data directly, but there's a better way.

[Yubico's website](https://developers.yubico.com/OTP/OTPs_Explained.html) has a
pretty good description of the structure of a OTP message, but in essence the
bits important to `ykvault` are as follows:

 * Cleartext bits:
    * Public UID (6 bytes)
 * Encrypted bits:
    * Private UID (6 bytes)
    * Session Counter
    * Usage Counter
    * CRC16

Firstly, the vault itself is encrypted with a master passphrase.  To gain
access, you must unseal the vault by providing this passphrase.  This decrypts
the vault contents.

The vault contains the public UID, counter values and key of each YubiKey known
to it.  The counter values are stored encrypted with a context key, derived
from the YubiKey's _private UID_ and another passphrase supplied by you.

When you supply a valid passphrase and OTP message to the `get_secret` method:

1. the OTP message is decrypted to extract the _private UID_
2. the private UID and passphrase are combined, the result used to derive a
   "context key".
3. the context data is decrypted
4. the counters are compared and validated, if the message is a repeat, we
   reject the OTP.
5. if counters match, the context key is returned.

### The nitty gritty

 * Symmetric cipher:
    * OTP message: `AES-128 ECB` (Yubico firmware requires this)
    * Vault and user data: `AES-256 CBC`
 * Key derivative function: `scrypt`
 * Vault file format: `cbor`

## Does it work?

Kinda.  There's currently some teething issues with block padding that isn't
quite working.  Not impossible to solve.

## Is it secure?

Probably not at this point, it's a proof-of-concept at this stage.  Use at your
own risk.

## Future plans

1. This code needs a UI to be truly useful.  Maybe ability to work with `cryfs`
   or `cryptsetup` so you can mount a USB stick using 2FA.
2. I'm using `scrypt` right now as the KDF, it'd be nice to support `argon2id`.
3. Rather than returning the context data, we should maybe store a salt in
   there with the counters, and use that in addition to the old counter value
   to derive a key that _actually_ encrypts user data.
4. Support for other encryption settings would be good.  Can't change what
   Yubico decided for the OTP messages, but everything else is in our control.
