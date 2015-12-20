# coding=utf-8
""" Quantum Resistant Cryptography - AES methodology"""
import os
import pyaes
from QRC.Common import data_hash


class AES:
    _osh = None
    _och = None
    _key = None
    _siv = None
    _civ = None

    def __init__(self, server_hash, client_hash):
        self._osh = server_hash
        self._och = client_hash
        self._cypher(server_hash + client_hash)

    def _cypher(self, seed):
        session_hash = data_hash(seed)
        self._key = session_hash[:32]
        self._siv = session_hash[32:48]
        self._civ = session_hash[48:64]

    @staticmethod
    def _pad(data):
        pad = 16 - len(data) % 16
        data += os.urandom(pad - 1) + chr(pad)
        return data

    @staticmethod
    def _unp(data):
        pad = data[len(data)-1] if len(data) > 0 else chr(0)
        return data[:len(data) - ord(pad)]

    def encrypt_server_data(self, msg):
        res = ""
        data = self._pad(msg)
        for i in range(0, len(data), 16):
            res += pyaes.AESModeOfOperationCBC(self._key, self._siv).encrypt(data[i:i + 16])
        self._cypher(self._siv + self._osh + self._civ + self._och + self._key)
        return res

    def decrypt_server_data(self, msg):
        data = ""
        for i in range(0, len(msg), 16):
            data += pyaes.AESModeOfOperationCBC(self._key, self._siv).decrypt(msg[i:i + 16])
        res = self._unp(data)
        self._cypher(self._siv + self._osh + self._civ + self._och + self._key)
        return res

    def encrypt_client_data(self, msg):
        res = ""
        data = self._pad(msg)
        for i in range(0, len(data), 16):
            res += pyaes.AESModeOfOperationCBC(self._key, self._civ).encrypt(data[i:i + 16])
        self._cypher(self._civ + self._och + self._siv + self._osh + self._key)
        return res

    def decrypt_client_data(self, msg):
        data = ""
        for i in range(0, len(msg), 16):
            data += pyaes.AESModeOfOperationCBC(self._key, self._civ).decrypt(msg[i:i + 16])
        res = self._unp(data)
        self._cypher(self._civ + self._och + self._siv + self._osh + self._key)
        return res
