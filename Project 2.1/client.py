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

def getResponse(sock, request, aes_seesion_key, initial_vector):

    sock.connect(bob_addr)

    # send 'hello' to Bob
    sendmsg(sock, "hello")

    # receive Bob's public key
    key = recvmsg(sock)
    server_public_key = serialization.load_pem_public_key(
        key, backend=default_backend()
    )

    # use Bob's public key to encrypt AES Session Key and Initial Vector 
    encoded_aes_seesion_key = rsa_encode(aes_seesion_key, server_public_key)
    encoded_initial_vector = rsa_encode(initial_vector, server_public_key)

    # send encrypted AES Session Key and Initial Vector 
    sendmsg(sock, encoded_aes_seesion_key)
    sendmsg(sock, encoded_initial_vector)

    # create AES encryptor and decryptor
    cipher = Cipher(algorithms.AES(aes_seesion_key), modes.CBC(initial_vector), backend=default_backend())
    aes_encryptor = cipher.encryptor()
    aes_decryptor = cipher.decryptor()

    # send encrypted request
    request_msg = aes_encryptor.update(request) + aes_encryptor.finalize()
    sendmsg(sock, request_msg)

    # receive Bob's encrypted response
    encrypted_response = recvmsg(sock)

    # receive "bye" from Bob
    recvmsg(sock)

    return encrypted_response

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as alice_sock, \
     socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bob_sock_sniff, \
     socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bob_sock_forge:

    # connect to Alice
    alice_sock.connect(alice_addr)

    # send student ID to Alice
    sendmsg(alice_sock, STUID)

    # receive "hello" from Alice
    recvmsg(alice_sock)

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

    # create AES decryptor
    cipher = Cipher(algorithms.AES(aes_seesion_key), modes.CBC(initial_vector), backend=default_backend())
    aes_decryptor = cipher.decryptor()

    # receive Alice's encrypted message and use Aes Session Key to decrypt
    alice_request = aes_decryptor.update(recvmsg(alice_sock)) + aes_decryptor.finalize()

    # strip null terminator
    d = json.loads(alice_request.decode('utf-8').strip('\0'))

    # modify the request
    d['Account_ID'] = STUID
    d['Authentication_Code'] = hashlib.sha256(STUID.encode('utf-8')).hexdigest()
    my_request = (my_padding(json.dumps(d))).encode('utf-8')

    encrypted_response_to_alice = getResponse(bob_sock_sniff, alice_request, aes_seesion_key, initial_vector)
    encrypted_response_to_me = getResponse(bob_sock_forge, my_request, aes_seesion_key, initial_vector)

    # send encrypted response to Alice
    sendmsg(alice_sock, encrypted_response_to_alice)

    # send 'bye' to Alice
    sendmsg(alice_sock, "bye")

    # decrypt message and print account money
    aes_decryptor = cipher.decryptor()
    response_to_alice = aes_decryptor.update(encrypted_response_to_alice) + aes_decryptor.finalize()
    d = json.loads(response_to_alice.decode('utf-8').strip('\0'))
    print("Alice money:", d["Account_Money"])

    aes_decryptor = cipher.decryptor()
    response_to_me = aes_decryptor.update(encrypted_response_to_me) + aes_decryptor.finalize()
    d = json.loads(response_to_me.decode('utf-8').strip('\0'))
    print("My money:", d["Account_Money"])