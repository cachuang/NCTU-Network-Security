import socket
import sys
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import hashlib
import json

alice_addr = ("140.113.194.88", 50000)
bob_addr = ("140.113.194.88", 50500)

STUID = "0556518"
BLOCK_SIZE = 16

my_padding = lambda s: s + (BLOCK_SIZE * int(len(s) / BLOCK_SIZE + 1) - len(s) % BLOCK_SIZE) * '\0'

# send size of message and message to destination
def sendmsg(sock, message):

    msg_size = len(message)
    byte_msg_size = struct.pack("i", msg_size)

    if type(message) == str: 
        message = bytes(message, 'utf-8') 

    sock.sendall(byte_msg_size)
    sock.sendall(message)

# receive size of message and message from destination
def recvmsg(sock):

    msg_size = struct.unpack("i", sock.recv(4))

    return sock.recv(int(msg_size[0]))

def rsa_encode(plaintext, key):

    return key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

def rsa_decrypt(ciphertext, key):

    return key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )    

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as alice_sock, \
     socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bob_sock  :

    alice_sock.connect(alice_addr)
    bob_sock.connect(bob_addr)

    # send student ID to Alice
    sendmsg(alice_sock, STUID)

    # receive "hello" from Alice
    recvmsg(alice_sock)

    # send 'hello' to Bob
    sendmsg(bob_sock, "hello")

    # receive Bob's public key
    msg = recvmsg(bob_sock)
    server_public_key = serialization.load_pem_public_key(
        msg, backend=default_backend()
    )

    # generate my public key and private key
    my_private_key = rsa.generate_private_key(
        public_exponent=3,
        key_size=1024,
        backend=default_backend()
    )
    my_public_key = my_private_key.public_key()

    # send my public key to Alice
    my_public_key_pem = my_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sendmsg(alice_sock, my_public_key_pem)

    # receive Alice's encrypted AES Session Key, Initial Vector and use my private key to decrypt
    aes_seesion_key = rsa_decrypt(recvmsg(alice_sock), my_private_key)
    initial_vector = rsa_decrypt(recvmsg(alice_sock), my_private_key)

    # create AES cipher
    cipher = Cipher(algorithms.AES(aes_seesion_key), modes.CBC(initial_vector), backend=default_backend())

    # receive Alice's encrypted message and use Aes Session Key to decrypt
    aes_decryptor = cipher.decryptor()
    alice_request = aes_decryptor.update(recvmsg(alice_sock)) + aes_decryptor.finalize()

    print("Alice request:\n\n", alice_request.decode('utf-8'))

    # strip null terminator
    d = json.loads(alice_request.decode('utf-8')[:-1])

    # modify the request
    d['Account_ID'] = STUID
    d['Authentication_Code'] = hashlib.sha256(STUID.encode('utf-8')).hexdigest()
    my_request = (my_padding(json.dumps(d))).encode('utf-8')

    # use server's public key to encrypt AES Session Key and Initial Vector 
    encoded_aes_seesion_key = rsa_encode(aes_seesion_key, server_public_key)
    encoded_initial_vector = rsa_encode(initial_vector, server_public_key)

    # send encrypted AES Session Key and Initial Vector 
    sendmsg(bob_sock, encoded_aes_seesion_key)
    sendmsg(bob_sock, encoded_initial_vector)

    # send encrypted message
    aes_encryptor = cipher.encryptor()
    request_msg = aes_encryptor.update(my_request) + aes_encryptor.finalize()
    sendmsg(bob_sock, request_msg)

    # receive Bob's encrypted message and use Aes Session Key to decrypt
    encrypted_bob_response = recvmsg(bob_sock)
    aes_decryptor = cipher.decryptor()
    bob_response = aes_decryptor.update(encrypted_bob_response) + aes_decryptor.finalize()

    print("\nBob response:\n\n", bob_response.decode('utf-8'))

    # receive "bye" from Bob
    recvmsg(bob_sock)

    # send encrypted message
    sendmsg(alice_sock, encrypted_bob_response)

    # send 'bye' to Alice
    sendmsg(alice_sock, "bye")



