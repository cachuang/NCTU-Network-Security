import socket
import sys
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

HOST, PORT = "140.113.194.88", 30000
STUID = "0556518"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

    sock.connect((HOST, PORT))

    # send handshake message 'hello'
    msg_size = len("hello")
    byte_msg_size = struct.pack("i", msg_size)

    sock.sendall(byte_msg_size)
    sock.sendall(bytes("hello", 'utf-8'))

    # receive server's public key
    msg_size = struct.unpack("i", sock.recv(4))

    server_public_key = serialization.load_pem_public_key(
        sock.recv(int(msg_size[0])),
        backend=default_backend()
    )

    # generate my public key and private key
    my_private_key = rsa.generate_private_key(
        public_exponent=3,
        key_size=1024,
        backend=default_backend()
    )
    my_public_key = my_private_key.public_key()

    # send my public key 
    my_public_key_pem = my_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    msg_size = len(my_public_key_pem)
    byte_msg_size = struct.pack("i", msg_size)

    sock.sendall(byte_msg_size)
    sock.sendall(my_public_key_pem)

    # use server's public key to encrypt message 
    plaintext = STUID.encode("utf-8")
    ciphertext = server_public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    # send encrypted message
    msg_size = len(ciphertext)
    byte_msg_size = struct.pack("i", msg_size)

    sock.sendall(byte_msg_size)
    sock.sendall(ciphertext)

    # receive server's encrypted message and use my private key to decrypt
    msg_size = struct.unpack("i", sock.recv(4))
    ciphertext = sock.recv(int(msg_size[0]))

    plaintext = my_private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    print("magic number: " + str(plaintext, "utf-8"))

    # receive "bye"
    msg_size = struct.unpack("i", sock.recv(4))
    sock.recv(int(msg_size[0]))