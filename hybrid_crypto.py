from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from Crypto.Cipher import AES

# Principal being a user of this hybrid cryptosystem.
class Principal:
    # key_length: RSA key length this principal will use
    # name: name of principal, save key under "name".der in DER format
    def __init__(self, key_length, name):
        self.key_length = key_length
        self.name = "name"
        # own_key: public/private key pair of owner (principal who can decrypt)
        self.own_key = self.create_rsa_key(key_length)
        # wb - write binary
        with open("{}.der".format(name), "wb") as out_fh:
            out_fh.write(self.own_key.exportKey(format ='DER', pkcs=1))

    # Create RSA key of given key_length
    def create_rsa_key(self, key_length):
        rsa_keypair = RSA.generate(key_length)
        return rsa_keypair

    # Return public key part of public/private key pair
    def get_public_key(self):
        public_key = self.own_key.publickey()
        return public_key

    # Send writes an encrypted message plus metadata to a file.
    # Input: filename = name of file to write to, eg "msg.enc"
    # msg = output of HybridCypher encrypt function [ck, cm, iv, pad_len]
    # ie encrypted symmetric key, encrypted message, IV, number of padding bytes
    # Read to file:
    # Line 1: RSA-encrypted symmetric key, as hex string.
    # Line 2: Symmetrically encrypted message, as hex string.
    # Line 3: IV as hex string
    # Line 4: Number of padding bytes (string of int)
    def send(self, filename, msg):
        lines = [bytes.hex(msg[0]), '\n', bytes.hex(msg[1]), '\n', bytes.hex(msg[2]), '\n', str(msg[3])]
        f = open(filename, 'w')
        f.writelines(lines)
        f.close()
        pass
    
    # Receive reads a hybrid-encrypted message from a file.
    # Returns: encrypted key (bytes), encrypted message (bytes), IV (bytes),
    # number of padding bytes
    def receive(self, filename):
        f = open(filename, 'r')
        lines = f.readlines()
        ck_bytes = bytes.fromhex(lines[0])
        cm_bytes = bytes.fromhex(lines[1])
        iv_bytes = bytes.fromhex(lines[2])
        pad_len_int = int(lines[3])
        return [ck_bytes, cm_bytes, iv_bytes, pad_len_int]

# HybridCipher uses both RSA and AES-CBC.
class HybridCipher:
    # Input:
    # length_sym: length of symmetric key. Must be 128, 192, or 256.
    # own_key: public/private key pair of owner (principal who can decrypt)
    # remote_pub_key: public key of principal this hybrid cipher is encrypting to
    def __init__(self, length_sym, own_key, remote_pub_key):
        self.length_sym = length_sym
        self.own_key = own_key
        self.remote_pub_key = remote_pub_key
        pass

    # Creates an AES (advanced encryption standard) cipher
    # in CBC (cipher block chaining) mode with random IV, and random key
    # Returns: cipher, IV, symmetric key
    def create_aes_cipher(self, length):
        sym_key = Random.new().read(AES.block_size) # Key must be 16 bytes long
        iv = Random.new().read(AES.block_size) # IV must be 16 bytes long
        cipher = AES.new(sym_key, AES.MODE_CBC, iv)
        return cipher, iv, sym_key
    
    # Encrypts plaintext message
    # Input:
    # msg: To be encrypted - AES symmetric key, plaintext message, IV, number of padding bytes
    # Returns: encrypted symmetric key, encrypted message, IV, number of padding bytes
    def encrypt(self, msg):
        padded_msg, pad_len = self.pad(msg)
        aes_cipher, iv, sym_key = self.create_aes_cipher(16)
        rsa_cipher = PKCS1_OAEP.new(self.remote_pub_key)
        cm = aes_cipher.encrypt(padded_msg)
        ck = rsa_cipher.encrypt(sym_key)
        return [ck, cm, iv, pad_len]
    
    # Decrypt hybrid-encrypted msg
    # Input: msg - output of receive(), ie encrypted key (bytes), encrypted message (bytes), IV (bytes),
    # number of padding bytes
    # Returns: decrypted message with padding removed, as string
    def decrypt(self, msg):
        enc_key = msg[0]
        enc_msg = msg[1]
        iv = msg[2]
        pad_len = msg[3]
        # Use private key to decrypt enc_key self.own_key
        rsa_cipher = PKCS1_OAEP.new(self.own_key)
        sym_key = rsa_cipher.decrypt(enc_key)
        aes_cipher = AES.new(sym_key, AES.MODE_CBC, iv=iv)
        plain_text = aes_cipher.decrypt(enc_msg)
        rcvd_msg_dec = self.strip_pad(plain_text, pad_len)
        return rcvd_msg_dec

    # Padding for AES-CBC.
    # Pad up to multiple of block length by adding 0s (as byte)
    # Returns: padded message, number of padding bytes
    def pad(self, msg):
        pad = '0'
        # AES block size is 16 bytes
        pad_len = 16 - len(msg) % 16
        cushion = pad * pad_len
        padded_msg = cushion + msg
        padded_msg = padded_msg.encode()
        # Pad length, number of bytes
        pad_len_int = len(cushion.encode())
        return padded_msg, pad_len_int

    # Strips padding and converts message to str.
    def strip_pad(self, msg, pad_len_int):
        msg_str = str(msg)
        msg_unpadded = msg_str[pad_len_int + 2 : len(msg_str)-1]
        return msg_unpadded

def main():
    # Create Alice as a principal. In this example, we choose a
    # 2048 bit RSA key.
    alice = Principal(2048, "alice")
    # Create Bob as a principal.
    bob = Principal(2048, "bob")

    # Create a HybridCipher object for Alice to use.
    # She uses her own public/private key pair and Bob's public key because he is the receiver.
    a_hybrid_cipher = HybridCipher(256, alice.own_key, bob.get_public_key())

    # Alice has a message for Bob.
    msg = "Hi Bob, it's Alice."

    # Alice uses the hybrid cipher to encrypt the message then sends it to Bob.
    msg_enc = a_hybrid_cipher.encrypt(msg)
    alice.send("msg.enc", msg_enc)

    # Bob receives the encrypted message.
    rcv_msg_enc = bob.receive("msg.enc")
    # Bob creates a HybridCipher.
    # He configures it with his own public/private key pair and Alice's public key.
    b_hybrid_cipher = HybridCipher(256, bob.own_key, alice.get_public_key())

    # Bob decrypts the message.
    dec_msg = b_hybrid_cipher.decrypt(rcv_msg_enc)
    
    # It says...
    print(dec_msg)
    
    if msg == dec_msg:
        print("This worked!")

main()
