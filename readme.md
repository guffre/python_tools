## stegopng.py

Python stegonography tool with builtin encryption/obfuscation of the data.
Places 6 bits of data into each pixel of a .png-type file.
Only tested with .png files, but will probably work with .bmp files as well.

Oh, it also encrypts the data. Nice.

## leet.py

This just generates "leet" word permutations. It uses an easily updatable dictionary if you have certain substitutions in mind.

## ssh_user_enum

This is PoC code for CVE-2018-15473 (OpenSSH < 7.7). The advantage of using *my* PoC code is that it allows threading, unlike the vast majority (or all?) other PoC codes you find out there using paramiko.

The reason mine allows threading is that it doesn't clobber the functionality of paramiko by temporarily replacing internal functions (looking at you, add_boolean PoC's).

## substitution_cipher.py

This is byte-substitution cipher code. I also included a variant that does substitution + encryption.
