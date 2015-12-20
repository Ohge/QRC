# coding=utf-8
""" Quantum Resistant Cryptography Client """
import socket
from QRC.Common import b64e, random_hash
from QRC.KeyRing import KeyRing
from QRC.AES import AES


class Client(object):
    _socket = None
    _running = False

    def __init__(self, server_address, callback, debug=False):
        temp_key = KeyRing()
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.connect((server_address[0], server_address[1]))
            self._running = True
            _client_handshake(self._socket, server_address, callback, temp_key, debug)
        except socket.error as msg:
            print "Error:", msg

    def close(self):
        if self._running is True:
            self._socket.close()
            self._running = False


class _Socket(object):
    connection = None
    session = None
    debug = False

    def __init__(self, connection, session=None, debug=False):
        self.connection = connection
        self.session = session
        self.debug = debug

    def show_debug(self, msg):
        if self.debug is True:
            if isinstance(msg, str):
                print msg
            else:
                print "\t".join(msg)

    def close(self, msg=""):
        self.connection.close()
        if msg != "":
            self.show_debug(msg)

    def send(self, d):
        if self.session is not None:
            sent = self.session.encrypt_server_data(d)
            self.connection.send(sent)
            self.show_debug(("Sent:", str(len(sent)), str(len(d)), d))
        else:
            self.connection.send(d)
            self.show_debug(("Sent:", str(len(d)), b64e(d)))

    def get(self, size=1040):
        raw_data = self.connection.recv(size)
        if len(raw_data) > 0:
            if self.session is not None:
                got = self.session.decrypt_client_data(raw_data)
                self.show_debug(("Got: ", str(len(raw_data)), str(len(got)), got))
                return got
            else:
                self.show_debug(("Got:", str(len(raw_data)), b64e(raw_data)))
                return raw_data
        else:
            self.close()


def _client_handshake(connection, server_address, callback, key_ring, debug):
    # INIT SESSION
    sock = _Socket(connection, debug=debug)
    sock.show_debug("connected")
    error_msg = "Handshake failed!"
    # PLAIN TEXT HANDSHAKE
    print "Starting plaintext ECC handshake"
    sock.send(key_ring.public_key())
    server_crypto = key_ring.peer(sock.get())
    if not server_crypto.validate():
        sock.close(error_msg)
        return
    # ENCRYPTED HASH EXCHANGE
    print "Starting encrypted ECC hash exchange"
    client_hash = random_hash()
    sock.send(key_ring.encrypt(server_crypto, client_hash))
    server_hash = key_ring.decrypt(server_crypto, sock.get())
    if len(server_hash) != 64:
        sock.close(error_msg)
        return
    # MAKE SHARED SESSION CYPHER
    sock.session = AES(server_hash, client_hash)
    sock.show_debug("AES cypher session started")
    # BEGIN ENCRYPTED SESSION
    callback(sock, server_address)
