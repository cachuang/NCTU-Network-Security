import socket
import sys
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST, PORT = "140.113.194.88", 45000
STUID = "0556518"
BLOCK_SIZE = 16

my_padding = lambda s: s + (BLOCK_SIZE * int(len(s) / BLOCK_SIZE + 1) - len(s) % BLOCK_SIZE) * '\0'

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

    sock.connect((HOST, PORT))

    # send handshake message 'hello' to server
    msg_size = len("hello")
    byte_msg_size = struct.pack("i", msg_size)

    sock.sendall(byte_msg_size)
    sock.sendall(bytes("hello", 'utf-8'))

    # receive "hello" from server
    msg_size = struct.unpack("i", sock.recv(4))
    sock.recv(int(msg_size[0]))

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

    # receive server's encrypted AES Session Key and use my private key to decrypt
    msg_size = struct.unpack("i", sock.recv(4))
    ciphertext = sock.recv(int(msg_size[0]))

    aes_seesion_key = my_private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    # receive server's encrypted Initial Vector and use my private key to decrypt
    msg_size = struct.unpack("i", sock.recv(4))
    ciphertext = sock.recv(int(msg_size[0]))

    initial_vector = my_private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    
    # send encrypted message
    cipher = Cipher(algorithms.AES(aes_seesion_key), modes.CBC(initial_vector), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(my_padding(STUID).encode("utf-8")) + encryptor.finalize()

    msg_size = len(ciphertext)
    byte_msg_size = struct.pack("i", msg_size)

    sock.sendall(byte_msg_size)
    sock.sendall(ciphertext)

    # receive server's encrypted message and use Aes Session Key to decrypt
    msg_size = struct.unpack("i", sock.recv(4))
    ciphertext = sock.recv(int(msg_size[0]))

    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    print("magic number: " + str(plaintext, "utf-8"))

    # receive "bye"
    msg_size = struct.unpack("i", sock.recv(4))
    sock.recv(int(msg_size[0]))