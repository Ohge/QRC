# coding=utf-8
""" Quantum Resistant Cryptography Client Test """
import QRC


def _client_callback(sock, server_address):
    print "Server", server_address, "completed handshake"
    print sock.get()
    sock.send("Hello server!")
    sock.close()

QRC.Client(
    server_address=('127.0.0.1', 9999),
    callback=_client_callback,
    debug=True
)
