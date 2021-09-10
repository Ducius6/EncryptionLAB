import os
from base64 import b64decode, b64encode
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA3_256, SHA3_512

supported_modes = {"cbc": AES.MODE_CBC, "ofb": AES.MODE_OFB}
supported_hash_algorithms = {"SHA3_256": SHA3_256, "SHA3_512": SHA3_512}


class SymmetricEncryption:
    def __init__(self, encryption="AES", key_length=16, mode="ofb"):
        if mode not in supported_modes:
            raise ValueError("Mode is not supported!")
        self.cipher_mode = supported_modes[mode]
        if encryption == "AES":
            self.cipher_class = AES
            self._key = os.urandom(key_length)
            self.iv = Random.new().read(self.cipher_class.block_size)
        elif encryption == "DES3":
            self.cipher_class = DES3
            self._key = os.urandom(3 * 8)
            self.iv = Random.new().read(self.cipher_class.block_size)
        else:
            raise ValueError("Encryption method not supported!")

    def encrypt(self, message):
        data = pad(message.encode("utf-8"), self.cipher_class.block_size)
        cipher = self.cipher_class.new(key=self._key, mode=self.cipher_mode, iv=self.iv)
        encrypted_data = cipher.encrypt(data)
        return b64encode(encrypted_data)

    def decrypt(self, message):
        data = b64decode(message)
        cipher = self.cipher_class.new(key=self._key, mode=self.cipher_mode, iv=self.iv)
        return unpad(cipher.decrypt(data), self.cipher_class.block_size).decode("utf-8")

    def decrypt_with_key(self, message, key):
        data = b64decode(message)
        cipher = self.cipher_class.new(key=key, mode=self.cipher_mode, iv=self.iv)
        return unpad(cipher.decrypt(data), self.cipher_class.block_size).decode("utf-8")


class AsymmetricEncryption:
    def __init__(self, key_length=3072):
        self.cipher_class = RSA
        self._key_pair = RSA.generate(bits=key_length)

        self.public_key = self._key_pair.public_key()

        self.e = self._key_pair.e
        self.d = self._key_pair.d
        self.n = self._key_pair.n

    @staticmethod
    def encrypt(message, public_key):
        encryptor = PKCS1_OAEP.new(public_key)
        encrypted = encryptor.encrypt(message)
        return encrypted

    def decrypt(self, encrypted):
        decryptor = PKCS1_OAEP.new(self._key_pair)
        decrypted = decryptor.decrypt(encrypted)
        return decrypted

    def sign(self, msg_hash):
        signed_message = pkcs1_15.new(self._key_pair).sign(msg_hash)
        return signed_message

    @staticmethod
    def verify(signature, msg_hash, public_key):
        try:
            pkcs1_15.new(public_key).verify(msg_hash, signature)
            print("Signature is valid!")
            return True
        except(ValueError, TypeError):
            print("Signature is not valid!")
            return False


def packDigitalEnvelope(message, symmetric, receiver_key):
    encrypted_message = symmetric.encrypt(message)
    encrypted_key = AsymmetricEncryption.encrypt(symmetric._key, receiver_key)
    return encrypted_message, encrypted_key


def unpackDigitalEnvelope(encrypted_message, encrypted_key, asymmetric, symmetric):
    key = asymmetric.decrypt(encrypted_key)
    message = symmetric.decrypt_with_key(encrypted_message, key)
    return message


def signDigitalSignature(message, asymetric, hash_algorithm):
    if hash_algorithm not in supported_hash_algorithms:
        raise ValueError("Hash algorithm not supported!")
    msg_hash = supported_hash_algorithms[hash_algorithm].new(message)
    signed_message = asymetric.sign(msg_hash)
    return message, signed_message


def verifyDigitalSignature(message, signature, public_key, hash_algorithm):
    if hash_algorithm not in supported_hash_algorithms:
        raise ValueError("Hash algorithm not supported!")
    msg_hash = supported_hash_algorithms[hash_algorithm].new(message)
    return AsymmetricEncryption.verify(signature, msg_hash, public_key)


def digitalStamp(message, symmetric, receiver_key, asymmetric, hash_algorithm):
    encrypted_message, encrypted_key = packDigitalEnvelope(message, symmetric, receiver_key)
    msg_and_key = encrypted_message + encrypted_key
    _, signed_message = signDigitalSignature(msg_and_key, asymmetric,
                                             hash_algorithm)
    return encrypted_message, signed_message, encrypted_key


def verifyAndDecryptDigitalStamp(encrypted_message, signature, public_key, hash_algorithm, encrypted_key, asymmetric,
                                 symmetric):
    message = unpackDigitalEnvelope(encrypted_message, encrypted_key, asymmetric, symmetric)
    msg_and_key = encrypted_message + encrypted_key
    isValid = verifyDigitalSignature(msg_and_key, signature, public_key, hash_algorithm)
    return message, isValid


msg = "Neka kriptirana poruka"


def digitalEnvelopeExample(encryption="AES", key_length=32, mode="ofb"):
    symmetric_cipher = SymmetricEncryption(encryption, key_length, mode)
    rsa_cipher_receiver = AsymmetricEncryption()

    # Sender creating digital envelope
    encrypted_message, encrypted_key = packDigitalEnvelope(msg, symmetric_cipher, rsa_cipher_receiver.public_key)

    print("Kriptiranana poruka: " + str(encrypted_message))
    print("Kriptirani kljuc: " + str(encrypted_key))

    # Receiver decrypting digital envelope
    message = unpackDigitalEnvelope(encrypted_message, encrypted_key, rsa_cipher_receiver, symmetric_cipher)
    print("Dekriptirana poruka iz omotnice: " + message)


#digitalEnvelopeExample()


def digitalSignatureExample(hash_algorithm="SHA3_256"):
    rsa_cipher_sender = AsymmetricEncryption()

    # Sender signing message
    message, signature = signDigitalSignature(msg.encode("utf-8"), rsa_cipher_sender, hash_algorithm)

    print("Digitalni potpis: " + str(signature))
    print("Potpisana poruka: " + message.decode("utf-8"))
    fake_signature = signature + bytes(1)

    # Receiver verifying message
    print(verifyDigitalSignature(message, signature, rsa_cipher_sender.public_key, hash_algorithm))


# digitalSignatureExample()


def digitalStampExample(encryption="AES", key_length=16, mode="cbc", hash_algorithm="SHA3_256"):
    symmetric_cipher = SymmetricEncryption(encryption, key_length, mode)
    rsa_cipher_sender = AsymmetricEncryption()
    rsa_cipher_receiver = AsymmetricEncryption()

    # Sender making digital stamp
    encrypted_message, signature, encrypted_key = digitalStamp(msg, symmetric_cipher, rsa_cipher_receiver.public_key,
                                                               rsa_cipher_sender, hash_algorithm)

    print("Digitalni potpis: " + str(signature))
    print("Enkriptirana poruka: " + str(encrypted_message))
    print("Enkriptirani kljuc: " + str(encrypted_key))
    fake_signature = signature + bytes(1)

    # Receiver decrypting and verifying digital stamp
    message, isValid = verifyAndDecryptDigitalStamp(encrypted_message, signature, rsa_cipher_sender.public_key,
                                                    hash_algorithm,
                                                    encrypted_key, rsa_cipher_receiver, symmetric_cipher)

    print("Dekriptirana poruka: " + message)

digitalStampExample()
