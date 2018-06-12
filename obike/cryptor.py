from Crypto.Cipher import AES
from Crypto.Hash import SHA

enc_key = 'oBAddMYFUzLed'
enc_iv = '1234567890123456'
hash_key = 'oBaddX4buhBMG'
blocksize = 16


class Cryptor(object):

    def __init__(self, version='2.5.4'):
        self.version = version.replace('.', '')

    def decrypt(self, ciphertext, validate=True):
        cipher = AES.new(enc_key + self.version, AES.MODE_CBC, enc_iv)
        plaintext = self.unpad(cipher.decrypt(ciphertext.decode('hex')))
        data, ha5h = plaintext.rsplit('&', 1)
        if validate:
            computed = self.hash(data + '&')
            if computed != ha5h:
                raise Exception('validation failed')
        return data

    def encrypt(self, plaintext):
        plaintext = plaintext + '&' + self.hash(plaintext + '&')
        cipher = AES.new(enc_key + self.version, AES.MODE_CBC, enc_iv)
        return cipher.encrypt(self.pad(plaintext)).encode('hex')

    def hash(self, s):
        hasher = SHA.new()
        hasher.update(s + hash_key + self.version)
        return hasher.hexdigest()

    def pad(self, s):
        size = blocksize - len(s) % blocksize
        return s + size * chr(size)

    def unpad(self, s):
        return s[:-ord(s[len(s)-1:])]

