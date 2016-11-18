import socket
import sys
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import NameOID

CA_ADDR = ("140.113.194.88", 20000)
GAME_DOWNLOADER_ADDR = ("140.113.194.88", 20500)
STUID = "0556518"
BLOCK_SIZE = 16

my_padding = lambda s: s + (BLOCK_SIZE * int(len(s) / BLOCK_SIZE + 1) - len(s) % BLOCK_SIZE) * '\0'

# recv exactly n bytes
def recvall(sock, n):

    data = b''

    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet

    return data

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
    return recvall(sock, int(msg_size[0]))

def rsa_decrypt(ciphertext, key):

    return key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )    

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ca_sock, \
     socket.socket(socket.AF_INET, socket.SOCK_STREAM) as game_downloader_sock:

    # connect to CA
    ca_sock.connect(CA_ADDR)

    # send student ID to CA
    sendmsg(ca_sock, STUID)

    # receive "hello" from CA
    recvmsg(ca_sock)

    # generate my public key and private key
    my_private_key = rsa.generate_private_key(
        public_exponent=3,
        key_size=1024,
        backend=default_backend()
    )
    my_public_key = my_private_key.public_key()

    # generate certificate signing request
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, STUID)
    ])).sign(
        my_private_key, hashes.SHA256(), default_backend()
    )

    # send CSR to CA in pem foramat
    sendmsg(ca_sock, csr.public_bytes(serialization.Encoding.PEM))

    # receive certificate from CA
    cert_pem = recvmsg(ca_sock)

    # receive bye from CA
    recvmsg(ca_sock)

    # connect to GameDownloader
    game_downloader_sock.connect(GAME_DOWNLOADER_ADDR)

    # send student ID to GameDownloader
    sendmsg(game_downloader_sock, STUID)

    # receive "hello" from GameDownloader
    recvmsg(game_downloader_sock)

    # send certificate to GameDownloader in pem format
    sendmsg(game_downloader_sock, cert_pem)

    # receive "PASS" from GameDownloader
    recvmsg(game_downloader_sock)

    # receive GameDownloader's encrypted AES Session Key, Initial Vector and use my private key to decrypt
    aes_seesion_key = rsa_decrypt(recvmsg(game_downloader_sock), my_private_key)
    initial_vector = rsa_decrypt(recvmsg(game_downloader_sock), my_private_key)

    # create AES decryptor
    cipher = Cipher(algorithms.AES(aes_seesion_key), modes.CBC(initial_vector), backend=default_backend())
    aes_decryptor = cipher.decryptor()

    # receive Game Binary and use Aes Session Key to decrypt
    encrypted_game = recvmsg(game_downloader_sock)
    game = aes_decryptor.update(encrypted_game) + aes_decryptor.finalize()

    with open("game", "wb") as f:
        f.write(game)

    print('Download Complete. File named "game" is in the current working directory')

    # send "bye" to GameDownloader
    sendmsg(game_downloader_sock, "bye")