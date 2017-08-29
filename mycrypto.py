import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

int_det_iv = b'\xddj\xed\x16~\x80@\x1a'
string_det_iv = b'&\x94<5\xd5\xd0n*\xb1c\xa0\xc3\x82\xea\x88\xb5'
backend = default_backend()


# 加密应该输入字节串，输出也是字节串吗?
def string_enc_rnd(text: bytes, key, iv):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return ct


def string_dec_rnd(ct: bytes, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(pt) + unpadder.finalize()
    return data


def string_enc_det(text: bytes, key):
    tmp = string_enc_rnd(text, key, string_det_iv)
    tmp = tmp[::-1]
    return string_enc_rnd(tmp, key, string_det_iv)


def string_dec_det(ct: bytes, key):
    tmp = string_dec_rnd(ct, key, string_det_iv)
    tmp = tmp[::-1]
    return string_dec_rnd(tmp, key, string_det_iv)


def int_enc_rnd(int64: bytes, key, iv):
    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(int64) + encryptor.finalize()
    return ct


def int_dec_rnd(et: bytes, key, iv):
    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    pt = decryptor.update(et) + decryptor.finalize()
    return pt


def int_enc_det(int64, key):
    return int_enc_rnd(int64, key, int_det_iv)


def int_dec_det(et, key):
    return int_dec_rnd(et, key, int_det_iv)


if __name__ == '__main__':
    key = os.urandom(32)
    a = string_dec_det(string_enc_det('赵柯'.encode(), key), key).decode()
    print(a)
    enc = int_enc_det(int(10).to_bytes(8, sys.byteorder), key)
    b = int_dec_det(enc, key)
    b = int.from_bytes(b, sys.byteorder)
    print(b)
