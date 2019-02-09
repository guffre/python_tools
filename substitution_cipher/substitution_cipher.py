import os
import random
from binascii import hexlify

def _bytesub(data, seed, encode):
    orig = range(256)
    random.seed(seed)
    swap = random.sample(orig, 256)
    if not isinstance(data, bytearray):
        data = bytearray(data)
    if encode:
        return bytearray([swap[x] for x in data])
    else:
        return bytearray([orig[swap.index(x)] for x in data])

def _byte_encsub(data, encode, password):
    orig = range(256)
    if not isinstance(data, bytearray):
        data = bytearray(data)
    if encode:
        seed = bytearray(os.urandom(len(password)))
        encseed = map(lambda x,y: chr(x^y), seed, bytearray(password))
        data = ''.join(encseed) + data
        seed = int(hexlify(seed),16)
    else:
        seed = map(lambda x,y: x^y, data[:len(password)], bytearray(password))
        seed = int(hexlify(bytearray(seed)),16)
    random.seed(seed)
    swap = random.sample(orig, 256)
    if encode:
        return data[:len(password)] + bytearray([swap[x]^random.randint(0,255) for x in data[len(password):]])
    else:
        return bytearray([orig[swap.index(x^random.randint(0,255))] for x in data[len(password):]])

def byte_sub_encode(data, seed):
    return _bytesub(data, seed, True)

def byte_sub_decode(data, seed):
    return _bytesub(data, seed, False)

def byte_sub_encrypt(data, password="bc0der"):
    return _byte_encsub(data, True, password)

def byte_sub_decrypt(data, password="bc0der"):
    return _byte_encsub(data, False, password)
