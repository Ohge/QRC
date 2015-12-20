# coding=utf-8
""" Quantum Resistant Cryptography Server Test """
import QRC


def _server_callback(sock, client_address):
    print "Client ", client_address, "completed handshake"
    sock.send("Hello client!")
    print sock.get()
    sock.close()

server = QRC.Server(
    local_address=('127.0.0.1', 9999),
    callback=_server_callback,
    debug=True
)
server.start()
server.stop()
