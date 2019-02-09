# substitution_cipher.py

This is byte-substitution cipher code. I also included a variant that does substitution + encryption.

## Some sample usage:
    test = "this is some sample text"
    password = "some sort of passphrase"

    enc = byte_sub_encrypt(test, password)
    dec = byte_sub_decrypt(enc, password)

    enc = byte_sub_encode(test, 42)
    dec = byte_sub_decode(enc, 42)