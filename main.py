import csv
import mycrypto
import os
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import copy
backend = default_backend()
master_key = b'\x10g i\xb3<\xc4\t\xfeR#[3i1\x0c'
id_rnd = True
name_rnd = True
enc_table = []


class SecLevel:
    INVALID, PLAINVAL, OPE, DETJOIN, DET, SEARCH, HOM, RND = range(0, 8)


# 根据洋葱名/当前安全层级/当前的列名生成密钥
def ken_gen(name, current_seclevel, column_name, length=32, mk=master_key):
    pw = name + str(current_seclevel) + column_name
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=mk,
        iterations=100000,
        backend=backend
    )
    current_key = kdf.derive(pw.encode())
    return current_key


def write_to_file(table):
    with open('encrypttext', 'w', newline='') as encrypt_file:
        fieldnames = ['ID_IV', 'ID_oDET', 'NAME_IV', 'NAME_oDET']
        writer = csv.writer(encrypt_file)
        writer.writerow(fieldnames)
        for row in enc_table:
            writer.writerow(row)


def enc_file_gen():
    table = []
    with open('plaintext', 'r', newline='') as plain_file:
        reader = csv.DictReader(plain_file)
        for row in reader:
            table.append([row['ID'], row['NAME']])

    with open('encrypttext', 'w', newline='') as encrypt_file:
        fieldnames = ['ID_IV', 'ID_oDET', 'NAME_IV', 'NAME_oDET']
        writer = csv.writer(encrypt_file)
        writer.writerow(fieldnames)
        for row in table:
            id_iv = os.urandom(8)

            enc_id = mycrypto.int_enc_det(int(row[0]).to_bytes(8, sys.byteorder),
                                          ken_gen('oDET', SecLevel.DET, 'ID_oDET'))

            enc_id = mycrypto.int_enc_rnd(enc_id, ken_gen('oDET', SecLevel.RND, 'ID_oDET'), id_iv)
            name_iv = os.urandom(16)
            enc_name = mycrypto.string_enc_det(row[1].encode(), ken_gen('oDET', SecLevel.DET, 'NAME_oDET'))

            enc_name = mycrypto.string_enc_rnd(enc_name, ken_gen('oDET', SecLevel.RND, 'NAME_oDET'), name_iv)
            writer.writerow([id_iv, enc_id, name_iv, enc_name])
            enc_table.append([id_iv, enc_id, name_iv, enc_name])


def adjust(col_name):
    global id_rnd
    global name_rnd
    key = ken_gen('oDET', SecLevel.RND, col_name + '_oDET')
    if col_name == 'ID':
        for row in enc_table:
            row[1] = mycrypto.int_dec_rnd(row[1], key, row[0])
            id_rnd = False
    if col_name == 'NAME':
        for row in enc_table:
            row[3] = mycrypto.string_dec_rnd(row[3], key, row[2])
            name_rnd = False
    write_to_file(enc_table)


def select(condition):  # 假设col_names为*
    if condition is None:
        return copy.deepcopy(enc_table)
    condition_col, value = condition[0].upper(), condition[1].strip("'")
    key = ken_gen('oDET', SecLevel.DET,  condition_col + '_oDET')
    result = []
    if condition_col == 'ID':
        enc_value = mycrypto.int_enc_det(int(value).to_bytes(8, sys.byteorder), key)
        for row in enc_table:
            if row[1] == enc_value:
                result.append(row)
    elif condition_col == 'NAME':
        enc_value = mycrypto.string_enc_det(value.encode(),key)
        for row in enc_table:
            if row[3] == enc_value:
                result.append(row)
    else:
        result = []
    return result


def decrypt_result(col_names, table):
    tmp = []
    for row in table:
        tmp_row = []
        dec_id = row[1]
        if id_rnd:
            dec_id = mycrypto.int_dec_rnd(row[1], ken_gen('oDET', SecLevel.RND, 'ID_oDET'), row[0])
        dec_id = mycrypto.int_dec_det(dec_id,
                                      ken_gen('oDET', SecLevel.DET, 'ID_oDET'))
        tmp_row.append(int.from_bytes(dec_id,sys.byteorder))
        dec_name = row[3]
        if name_rnd:
            dec_name = mycrypto.string_dec_rnd(row[3], ken_gen('oDET', SecLevel.RND, 'NAME_oDET'), row[2])
        dec_name = mycrypto.string_dec_det(dec_name,
                                           ken_gen('oDET', SecLevel.DET, 'NAME_oDET'))
        tmp_row.append(dec_name.decode())

        tmp.append(tmp_row)
    return tmp

enc_file_gen()
