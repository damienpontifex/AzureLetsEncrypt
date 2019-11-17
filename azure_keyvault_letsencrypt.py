# %%
# !python -m pip install -qU azure-mgmt-dns acme azure-keyvault
# python -m pip install -qU azure-keyvault-certificates azure-keyvault-keys azure-identity

# %%
import os
import hashlib
import base64
import logging
import datetime
from typing import List, Tuple, Optional, Callable, Generator

from OpenSSL import crypto

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

import josepy
from acme import messages, client
import acme

from azure.common.credentials import get_azure_cli_credentials

from azure.identity import DefaultAzureCredential, InteractiveBrowserCredential
from azure.keyvault.certificates import CertificateClient, CertificatePolicy, KeyType, SecretContentType
from azure.keyvault.keys import KeyClient
from azure.core.exceptions import ResourceNotFoundError
from azure.keyvault.keys.crypto import CryptographyClient, EncryptionAlgorithm

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

ChallengeHandler = Callable[[List[acme.messages.AuthorizationResource], josepy.JWKRSA], Generator[acme.messages.ChallengeResource, None, None]]

KEYVAULT_URL = os.environ.get('KEYVAULT_URL', 'https://pontivault.vault.azure.net/')
DNS_ZONE_RESOURCE_GROUP = os.environ.get('DNS_ZONE_RESOURCE_GROUP', 'damienpontifex.com-rg')
DNS_ZONE_NAME = os.environ.get('DNS_ZONE_NAME', 'damienpontifex.com')
REGISTRATION_EMAIL = os.environ.get('REGISTRATION_EMAIL', 'damien.pontifex@gmail.com')

#%%
def dns_challenge_handler(authorizations: List[acme.messages.AuthorizationResource], account_key: josepy.JWKRSA) -> Generator[acme.messages.ChallengeResource, None, None]:
    """Extract DNS challenges and ensure they're created in Azure DNS"""

    def _get_dns_challenge(authzr: acme.messages.AuthorizationResource) -> Tuple[acme.challenges.DNS01, str]:
        """Find DNS challenge from authorization challenge options"""
        challenge = next(c for c in authzr.body.challenges if type(c.chall) == acme.challenges.DNS01)
        return challenge, authzr.body.identifier.value

    # Select DNS-01 within offered challenges by the CA server
    dns_challenges = (_get_dns_challenge(auth_resource) for auth_resource in authorizations)

    #%%
    dns_auth, subscription_id = get_azure_cli_credentials() #resource='https://vault.azure.net')

    # %%
    from azure.mgmt.dns import DnsManagementClient

    def _create_dns_records(txt_record_name, txt_record_value, auth, subscription_id):
        """Create the DNS records to respond to challenge"""

        dns_client = DnsManagementClient(auth, subscription_id)
        
        dns_client.record_sets.create_or_update(
            resource_group_name=DNS_ZONE_RESOURCE_GROUP, zone_name=DNS_ZONE_NAME, 
            relative_record_set_name=txt_record_name, record_type='TXT', parameters={
                'ttl': 3600,
                'txtrecords': [
                    { 'value': [txt_record_value] }
                ]
            })

    #%%
    # Create the DNS records used for the challenge
    for dns_challenge, url in dns_challenges:
        # Drop the top level domain from the record value
        domain_prefix = '.'.join(url.split('.')[:-2])
        record_set_name = dns_challenge.chall.validation_domain_name(domain_prefix)
        record_set_value = dns_challenge.chall.validation(account_key)

        _create_dns_records(record_set_name, record_set_value, dns_auth, subscription_id)

        yield dns_challenge


#%%
class KeyVaultRSAKey(rsa.RSAPublicKey, rsa.RSAPrivateKey):
    """Azure KeyVault provider for public and private account key"""

    def __init__(self, credentials, vault_url: str, key_name: str):
        self.vault_url = vault_url
        self.key_name = key_name

        self.kvclient = KeyClient(vault_url=KEYVAULT_URL, credential=credentials)

        try:
            self.kv_key = self.kvclient.create_rsa_key(key_name, size=self.key_size)
            self.kv_key = self.kvclient.get_key(key_name)
            logger.info('Using existing user key from KeyVault')
        except ResourceNotFoundError:
            logger.info('Creating new user key in KeyVault')

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
        res = self.crypto_client.sign(EncryptionAlgorithm.rsa_oaep_256, digest=value)
        return res.result


#%%
# def get_cert(*domains, use_prod=False, challenge_handler: ChallengeHandler):
    # """Follow certificate management flow https://tools.ietf.org/html/rfc8555#section-7"""

#%%
domains = ['test.damienpontifex.com', 'www.test.damienpontifex.com']
use_prod = False
challenge_handler = dns_challenge_handler

# %%
# Get directory
if use_prod:
    directory_url = 'https://acme-v02.api.letsencrypt.org/directory'
    user_key_name = 'acme'
    issuance_period_months = 3
else:
    directory_url = 'https://acme-staging-v02.api.letsencrypt.org/directory'
    user_key_name = 'acme-staging'
    issuance_period_months = 1

# %%
credential = DefaultAzureCredential()
credential = InteractiveBrowserCredential()

#%%
cert_client = CertificateClient(vault_url=KEYVAULT_URL, credential=credential)

#%% 
key = KeyVaultRSAKey(credential, KEYVAULT_URL, user_key_name)

#%%
account_key = josepy.JWKRSA(key=key)
client_network = acme.client.ClientNetwork(account_key)

#%%
directory = messages.Directory.from_json(client_network.get(directory_url).json())

#%%
client = acme.client.ClientV2(directory, client_network)

#%%
new_regr = acme.messages.Registration.from_data(
    key=account_key, email=REGISTRATION_EMAIL, terms_of_service_agreed=True)

# %%
# Register or fetch account
try:
    regr = client.new_account(new_regr)
    logger.info('Created new account')
except acme.errors.ConflictError as e:
    regr = acme.messages.RegistrationResource(uri=e.location, body=new_regr)
    regr = client.query_registration(regr)
    logger.info('Got existing account')

#%%
# from azure.keyvault.models import CertificatePolicy, CertificateAttributes, X509CertificateProperties, SubjectAlternativeNames

kv_cert_name = domains[0].replace('.', '')

#x509_cert_properties = X509CertificateProperties(subject='', subject_alternative_names=SubjectAlternativeNames(dns_names=domains), validity_in_months=issuance_period_months)
#cert_policy = CertificatePolicy(x509_certificate_properties=x509_cert_properties)

cert_policy = CertificatePolicy(
    issuer_name='letsencrypt',
    subject_name=f'CN={domains[0]}',
    exportable=True,
    key_type=KeyType.RSA,
    key_size=2048,
    content_type=SecretContentType.PKCS12,
    san_dns_names=domains[1:],
    validity_in_months=issuance_period_months
)
cert_op = cert_client.begin_create_certificate(name=kv_cert_name, policy=cert_policy)
# cert_op = kvclient.create_certificate(KEYVAULT_URL, certificate_name=kv_cert_name, certificate_policy=cert_policy)
cert_op = cert_op.result()

logger.info('Created certificate request in key vault')

#%%
# Wrap with header and footer for pem to show certificate request
csr_pem = "-----BEGIN CERTIFICATE REQUEST-----\n" + base64.b64encode(cert_op.csr).decode() + "\n-----END CERTIFICATE REQUEST-----\n"

#%%
# Submit order
order_resource = client.new_order(csr_pem)
logger.info('Submitted order')

#%%
# Challenges from order
# Respond to challenges
challenges_to_respond_to = list(challenge_handler(order_resource.authorizations, account_key))

#%%
for dns_challenge in challenges_to_respond_to:
    # Perform challenge
    auth_response = client.answer_challenge(dns_challenge, dns_challenge.chall.response(account_key))

logger.info('Answered challenges')

#%%
# Poll for status
# Finalize order
# Download certificate
final_order = client.poll_and_finalize(order_resource)

logger.info('Finalised order')

#%%
# Strip header and footer of BEGIN/END CERTIFICATE
with open('cert.pem', 'w') as f:
    f.write(final_order.fullchain_pem)
certificate_vals = [val.replace('\n', '').encode() for val in final_order.fullchain_pem.split('-----') 
                    if 'CERTIFICATE' not in val and len(val.replace('\n', '')) != 0]

#%%
cert_client.merge_certificate(name=kv_cert_name, x509_certificates=certificate_vals)
# kvclient.merge_certificate(KEYVAULT_URL, certificate_name=kv_cert_name, x509_certificates=certificate_vals)

logger.info('Merged certificate back to key vault')

# %%
# get_cert('test.damienpontifex.com', 'www.test.damienpontifex.com', 
#     use_prod=False, challenge_handler=dns_challenge_handler)
