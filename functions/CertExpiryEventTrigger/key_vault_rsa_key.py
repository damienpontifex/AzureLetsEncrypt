import logging
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from azure.keyvault.keys import KeyClient
from azure.core.exceptions import ResourceNotFoundError
from azure.keyvault.keys.crypto import CryptographyClient, EncryptionAlgorithm, SignatureAlgorithm

logger = logging.getLogger(__name__)

class KeyVaultRSAKey(rsa.RSAPublicKey, rsa.RSAPrivateKey):
    """Azure KeyVault provider for public and private account key"""

    def __init__(self, credentials, vault_url: str, key_name: str):
        self.vault_url = vault_url
        self.key_name = key_name

        self.key_client = KeyClient(vault_url=vault_url, credential=credentials)

        try:
            self.kv_key = self.key_client.get_key(key_name)
            logger.info('Using existing user key from KeyVault')
        except ResourceNotFoundError:
            logger.info('Creating new user key in KeyVault')
            self.kv_key = self.key_client.create_rsa_key(key_name, size=self.key_size)

        self.crypto_client = CryptographyClient(self.kv_key, credential=credentials)

    @property
    def key_size(self):
        return 2048

    def encrypt(self, plaintext, padding):
        result = self.crypto_client.encrypt(EncryptionAlgorithm.rsa_oaep, plaintext)
        return result
    
    def public_numbers(self):
        e = int.from_bytes(self.kv_key.key.e, byteorder='big')
        n = int.from_bytes(self.kv_key.key.n, byteorder='big')
        return rsa.RSAPublicNumbers(e, n)

    def public_bytes(self):
        pass
    
    def verifier(self, signature, padding, algorithm):
        pass

    def verify(self, signature, data, padding, algorithm):
        pass

    def public_key(self):
        return self
    
    def signer(self, padding, algorithm):
        pass

    def decrypt(self, ciphertext, padding):
        pass

    def sign(self, data, padding, algorithm):
        value = hashlib.sha256(data).digest()
        res = self.crypto_client.sign(SignatureAlgorithm.rs256, digest=value)
        return res.signature