"""
module2_crypto - Cryptography for the secure mode of the Smart Building.

    keygen.py              secure random keys (secrets / os.urandom) + HKDF sub-keys
    aes_gcm.py             AES-256-GCM authenticated encryption
    integrity.py           SHA-256 hashing and HMAC-SHA256
    signatures.py          ECDSA P-256 digital signatures (signed door commands)
    key_manager.py         encrypted key storage, rotation, revocation
    challenge_response.py  device authentication without sending the key
    secure_channel.py      puts it all together into one protected message format
    crypto_broker.py       broker that enforces authentication, integrity, freshness
    benchmark.py           AES-GCM vs ChaCha20-Poly1305 speed and size comparison
    demo.py                key rotation / revocation demo printed by main.py

All primitives come from the 'cryptography' library - we never invent our own crypto.
"""
