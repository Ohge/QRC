# coding=utf-8
""" Quantum Resistant Cryptography Common """
import os
import base64
import hashlib


def b64e(data):
    return base64.urlsafe_b64encode(data)


def b64d(data):
    return base64.urlsafe_b64decode(data)


def random_hash():
    return data_hash(os.urandom(64))


def data_hash(d):
    return hashlib.sha512(d).digest()
