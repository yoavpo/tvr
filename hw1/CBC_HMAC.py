"""
Python implementation of CBC HMAC authenticated encryption
"""

from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac


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
        padding_length = self.block_len - (len(data) + 1) % self.block_len
        return data + self.__generate_padding(padding_length) + bytes([padding_length])

    def __auth(self, data):
        """
        Call HMAC_SHA_256
        """
        h = hmac.HMAC(self.mac_key, hashes.SHA256())
        h.update(data)
        return h.finalize()

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
        plaintext = self.__pad(data + tag[:-16])
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

        if stripped is None:
            return None

        data, tag = stripped[:-16], stripped[-16:]
        is_valid = tag == self.__auth(aad + data)[:-16]

        return data if is_valid else None


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
