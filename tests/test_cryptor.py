import unittest

from obike.cryptor import Cryptor


class TestCryptor(unittest.TestCase):

    def setUp(self):
        self.cryptor = Cryptor('2.5.4')

    def test_pad(self):
        padded = self.cryptor.pad('asdf')
        self.assertEquals(len(padded), 16)

    def test_unpad(self):
        unpadded = self.cryptor.unpad('asdf' + '\x0c'*12)
        self.assertEquals(unpadded, 'asdf')

    def test_hash(self):
        ha5h = '687fdcb704d0661b67cf1a297b5059b1d4d67900'
        text = '{"phone":"791234567","deviceId":"0123456789abc-0123456789abcdef01","password":"swordfish","countryCode":"41","dateTime":"1515100814123"}&'
        ha5h2 = self.cryptor.hash(text)
        self.assertEquals(ha5h, ha5h2)

    def test_encrypt(self):
        ciphertext = "e4526007ae3791e4fabdd5f6833563f8499d076fe5a4039e1ac1bcb7788dc7a053e8b4384faf202828e6587bbc4bf32f505429129871253ecc388b493f32368ac418f627acc7720c1b5e1a4ecc35fca7e80dd99062c24cea0b920fcc297164f8703511520f05c2f91ada946dbee9320a0d2f24f1101036133d53425e91f2b52b7abbea95cde3f395ce8f2c586aa1ea9eaa35fecb26214eb498dbd35c56d37b88ebdc100180da662cdae6d6aa50c31d2f92063c2acb8ff45f62d12d34005d48a3"
        plaintext = '{"phone":"791234567","deviceId":"0123456789abc-0123456789abcdef01","password":"swordfish","countryCode":"41","dateTime":"1515100814123"}'
        ciphertext2 = self.cryptor.encrypt(plaintext)
        self.assertEquals(ciphertext, ciphertext2)

    def test_decrypt(self):
        ciphertext = "e4526007ae3791e4fabdd5f6833563f8499d076fe5a4039e1ac1bcb7788dc7a053e8b4384faf202828e6587bbc4bf32f505429129871253ecc388b493f32368ac418f627acc7720c1b5e1a4ecc35fca7e80dd99062c24cea0b920fcc297164f8703511520f05c2f91ada946dbee9320a0d2f24f1101036133d53425e91f2b52b7abbea95cde3f395ce8f2c586aa1ea9eaa35fecb26214eb498dbd35c56d37b88ebdc100180da662cdae6d6aa50c31d2f92063c2acb8ff45f62d12d34005d48a3"
        plaintext = '{"phone":"791234567","deviceId":"0123456789abc-0123456789abcdef01","password":"swordfish","countryCode":"41","dateTime":"1515100814123"}'
        plaintext2 = self.cryptor.decrypt(ciphertext)
        self.assertEquals(plaintext, plaintext2)


if __name__ == '__main__':
    unittest.main()
