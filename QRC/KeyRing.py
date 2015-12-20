# coding=utf-8
""" Quantum Resistant Cryptography - ECC Key Ring"""
import os
import sys
import ecc.Key


class KeyRing(object):
    # CONSTANTS
    KEY_SIZE = 521

    # LOCAL VARS
    _key_pair = None

    def __init__(self, key_file=None, pass_phrase=None):
        # NO FILE USED
        if key_file is None:
            self._key_pair = self.new()
        # EXISTING FILE USED
        elif os.path.isfile(key_file):
            key_data = None
            try:
                with open(key_file) as file_handle:
                    key_data = file_handle.read(1024)
            except IOError as e:
                print "IOError({0}): {1}".format(e.errno, e.strerror)
            try:
                # FIXME: Use pass phrase decryption on key files
                self._key_pair = ecc.Key.Key.decode(key_data)
            except ValueError:
                print "KeyError: This file is not a valid key file"
                sys.exit(1)
        # CREATING NEW FILE FOR FIRST USE
        else:
            self._key_pair = self.new()
            key_data = self._key_pair.encode(include_private=True)
            # FIXME: Use pass phrase encryption on key files
            try:
                with open(key_file, 'w') as file_handle:
                    file_handle.write(key_data)
            except IOError as e:
                print "IOError({0}): {1}".format(e.errno, e.strerror)

    def new(self):
        # FIXME: Some keys validate, but signatures fail (github issue for pyecc module)
        while 1:
            kp = ecc.Key.Key.generate(self.KEY_SIZE)
            st = chr(0)
            lt = chr(255) * 64
            if kp.verify(st, kp.sign(st)) and kp.verify(lt, kp.sign(lt)):
                return kp
            else:
                with open("bad_keys.log", 'a') as file_handle:
                    file_handle.write(kp.encode(True) + "\n")

    def peer(self, public_key):
        return self._key_pair.decode(public_key)

    def public_key(self):
        return self._key_pair.encode()

    def encrypt(self, receiver, message):
        return self._key_pair.auth_encrypt(message, receiver)

    def decrypt(self, sender, message):
        return self._key_pair.auth_decrypt(message, sender)

    def sign(self, data):
        return self._key_pair.sign(data)

    def confirms(self, data, signature):
        return self._key_pair.verify(data, signature)
