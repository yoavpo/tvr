"""
Python implementation of CBC HMAC authenticated encryption
"""

from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac

FAIL = '!'

class AEAD(object):
    """
    Authenticated encryption and decryption
    """
    def __init__(self, block_len, mac_key, enc_key):
        self.block_len = block_len
        self.mac_key = mac_key
        self.enc_key = enc_key

    def authenticated_enc(self, data, aad, nonce):
        """
        Authenticated encryption
        :param data: input data
        :param aad: additional associated data
        :param nonce: nonce
        :return: c, the result of authenticated encryption
        """
        raise NotImplementedError("Must override authenticated_enc")



    def authenticated_dec(self, c, aad, nonce):
        """
        Authenticated decryption
        :param c: ciphertext
        :param aad: additional associated data
        :param nonce: nonce
        :return: decrypted data if verification succeeds, fail state else.
        """

        raise NotImplementedError("Must override authenticated_dec")


class AEAD_AES_128_CBC_HMAC_SHA_256(AEAD):
    def __init__(self, *args):
        self.block_len = 16
        self.mac_len = 16
        super(AEAD_AES_128_CBC_HMAC_SHA_256, self).__init__(self.block_len, *args)

    @staticmethod
    def __generate_padding(padding_length):
        return bytes([padding_length]) * padding_length

    def __strip_padding(self, data):
        """
        Strip all padding from the data
        :param data: input data
        :return: stripped data
        """
        padding_length = data[-1]
        padding_start = -1 - padding_length
        padding = data[padding_start:-1]
        is_valid = padding == self.__generate_padding(padding_length)

        return data[:padding_start] if is_valid else None

    def __pad(self, data):
        """
        Pad the data so that the block size is a multiple of block_len
        :param data: input data
        :return: padded data with length an integral multiple of block_len
        """
        padding_length = 16 - (len(data) + 1) % 16
        return data + self.__generate_padding(padding_length) + bytes([padding_length])

    def __auth(self, data):
        """
        Call HMAC_SHA_256
        """
        h = hmac.HMAC(self.mac_key, hashes.SHA256())
        h.update(data)
        return h.finalize()[-16:]

    def __encrypt(self, p, nonce):
        """
        Encrypt using AES_128_CBC
        """
        cipher = Cipher(algorithms.AES(self.enc_key), modes.CBC(nonce))
        encryptor = cipher.encryptor()
        return encryptor.update(p) + encryptor.finalize()

    def __decrypt(self, c, nonce):
        """
        Decrypt using AES_128_CBC
        """
        cipher = Cipher(algorithms.AES(self.enc_key), modes.CBC(nonce))
        decryptor = cipher.decryptor()
        return decryptor.update(c) + decryptor.finalize()

    def authenticated_enc(self, data, aad, nonce):
        """
        Authenticated encryption
        :param data: input data
        :param aad: additional associated data
        :param nonce: nonce
        :return: c, the result of authenticated encryption
        """
        tag = self.__auth(aad + data)
        plaintext = self.__pad(data + tag)
        return self.__encrypt(plaintext, nonce)


    def authenticated_dec(self, c, aad, nonce):
        """
        Authenticated decryption
        :param c: ciphertext
        :param aad: additional associated data
        :param nonce: nonce
        :return: decrypted data if verification succeeds, fail state else.
        """
        plaintext = self.__decrypt(c, nonce)
        stripped = self.__strip_padding(plaintext)
        data, tag = stripped[:-16], stripped[-16:]
        is_valid = tag == self.__auth(aad + data)

        return data if is_valid else FAIL


if __name__ == "__main__":
    data = b'secret data'
    aad = b'more data'
    mac_key = urandom(16)
    enc_key = urandom(16)
    aead = AEAD_AES_128_CBC_HMAC_SHA_256(mac_key, enc_key)
    nonce = urandom(16)
    print(f"data = {data}")
    print(f"aad = {aad}")
    print(f"mac_key = {mac_key}")
    print(f"enc_key = {enc_key}")
    print(f"nonce = {nonce}")
    ciphertext = aead.authenticated_enc(data, aad, nonce)
    print(f"ciphertext = {ciphertext}")

    p = aead.authenticated_dec(ciphertext, aad, nonce)
    print(p)
    print(len(data))
    print(len(ciphertext))

    # test vector
    print('\ntest vector\n')
    data = b"\xef8K\x17c\xb2hp\x1a$\xecS\x86\x9d\xbc\x11j\x01h\x15\xef\xbd,\xfd\xdc\xb4'\xc2\x03\xfa\t\x05\x81\xa3\xdf\xea*{\x8c\xe4\xbcRq\xe1\xfe\xc4\xd7\x12\x93qH\xff\xb8\xd1\x8f\xb8S\xae\xf6\x9c\xc7j{ 67\xfccH\xf4v)\x94\xa6\x14\xf7\xac\x94\xb4?\x1c_\x12Y\x94:Q\x9c\xa0\xd8n\xc6R\xdc\xc7W\xe2\xb0\x1c5"
    aad = b"{ \xff\x1b\xca\x98\xd0\xe5\xa55\xca\xa9\xd2U\x8a8\x90K4\x90\xb2\xfa\xa9?O\x80\xea\xa2\x85\xa2ECMEo(\x1f'\x01\xf1\xa4\xd4J\x9a\xfc\xf3\x89\x93\x86\xcf"
    mac_key = b'\x9e\xdf\xdd\xb1|;\xd4\xbc\xff\x03\xb7\tZy\xef\xeb'
    enc_key = b'\xdfei\xac\x86\xa5U_r\xff\r\x1c\x8d\x02\xac\x97'
    nonce = b'T\xbaS\x87M\x9dn\xca\xe8\xb0\xcfx\x8c@W\x87'

    ciphertext = aead.authenticated_enc(data, aad, nonce)
    print(f"ciphertext = {ciphertext}")

    expected_ciphertext = b"(\xfc.\xea\x17L\xadUez\x7f\xfb\x17V\xea;\xca\xb3\x1fK{\x01\xb4\xfc?&`,\xff3\xb1*\xab\xdf@\xd2o\x04\x9c\x82=9U\x8fJ'\x80\xd9\xc4V\xe3\x15v\xfb\xe2\x02\x13\x10\xf6\xe9\x0b\x17\xd4C1qUB\xd5\xd9\x17\x1b\x9a\xb9{,\x97\xbd\xb997M\xce\x82F\x04z\xa1*\x8a\n\xfb;\xe6|\x18}\x1d\x8f\xadT\x80\x00~k\xf7\xb0=\x8eH\\\xac\x8c\xd1\xb9#\x01m\xbe\xe9\x9b\x82[A\x11\xa2i\xe4"
    print(ciphertext == expected_ciphertext)
