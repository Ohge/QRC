# coding=utf-8
""" Quantum Resistant Cryptography Server """
import socket
import thread
from QRC.Common import b64e, random_hash
from QRC.KeyRing import KeyRing
from QRC.AES import AES


class Server(object):
    size = 4
    _keys = []
    _local_address = None
    _callback = None
    _debug = False
    _running = False
    _socket = None

    def __init__(self, local_address, callback, debug=False):
        self._local_address = local_address
        self._callback = callback
        self._debug = debug
        self._add_keys()

    def start(self):
        if self._running is False:
            try:
                # FIXME: autodetect IPv6 interfaces using self.local_address
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._socket.bind((self._local_address[0], self._local_address[1]))
                self._socket.listen(self.size)
                self._running = True
            except socket.error as msg:
                print msg
                return False
            print 'Starting server [' + self._local_address[0] + ':' + str(self._local_address[1]) + ']'
            while self._running is True:
                connection, ip = self._socket.accept()
                thread.start_new_thread(_handshake, (connection, ip, self._callback, self._keys.pop(0), self._debug))
                thread.start_new_thread(self._add_keys, ())

    def stop(self):
        if self._running is False:
            self._running = False
            self._socket.close()
            print 'Stopping server [' + self._local_address[0] + ':' + str(self._local_address[1]) + ']'

    def is_running(self):
        return self._running

    def _add_keys(self):
        while len(self._keys) < self.size:
            self._keys.append(KeyRing())


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
            sent = self.session.encrypt_client_data(d)
            self.connection.send(sent)
            self.show_debug(("Sent:", str(len(sent)), str(len(d)), d))
        else:
            self.connection.send(d)
            self.show_debug(("Sent:", str(len(d)), b64e(d)))

    def get(self, size=1040):
        raw_data = self.connection.recv(size)
        if len(raw_data) > 0:
            if self.session is not None:
                got = self.session.decrypt_server_data(raw_data)
                self.show_debug(("Got: ", str(len(raw_data)), str(len(got)), got))
                return got
            else:
                self.show_debug(("Got:", str(len(raw_data)), b64e(raw_data)))
                return raw_data
        else:
            self.close()


def _handshake(connection, client_address, callback, key_ring, debug):
    # INIT SESSION
    sock = _Socket(connection, debug=debug)
    sock.connection.settimeout(10)
    sock.show_debug("connected")
    error_msg = "Handshake failed!"
    # PLAIN TEXT HANDSHAKE
    sock.show_debug("Starting plaintext ECC handshake")
    client_crypto = key_ring.peer(sock.get())
    if not client_crypto.validate():
        sock.close(error_msg)
        return
    sock.send(key_ring.public_key())
    # ENCRYPTED HASH EXCHANGE
    sock.show_debug("Starting encrypted ECC hash exchange")
    client_hash = key_ring.decrypt(client_crypto, sock.get())
    if len(client_hash) != 64:
        sock.close(error_msg)
        return
    server_hash = random_hash()
    sock.send(key_ring.encrypt(client_crypto, server_hash))
    # MAKE SHARED SESSION CYPHER
    sock.session = AES(server_hash, client_hash)
    sock.show_debug("AES cypher session started")
    # BEGIN ENCRYPTED SESSION
    sock.connection.settimeout(None)
    thread.start_new_thread(callback, (sock, client_address))
