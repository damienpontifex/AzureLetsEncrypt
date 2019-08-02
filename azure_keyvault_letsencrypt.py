# %%
# !python -m pip install -qU azure-mgmt-dns acme azure-keyvault

# %%
import os
import hashlib
from typing import List, Tuple, Optional, Callable, Generator

from OpenSSL import crypto

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

import josepy
from acme import messages, client
import acme

from azure.common.credentials import get_azure_cli_credentials
from azure.keyvault import KeyVaultClient
from azure.keyvault.models import KeyVaultErrorException

ChallengeHandler = Callable[[List[acme.messages.AuthorizationResource], josepy.JWKRSA], Generator[acme.messages.ChallengeResource, None, None]]

KEYVAULT_URL = os.environ.get('KEYVAULT_URL', 'https://pontivault.vault.azure.net/')
DNS_ZONE_RESOURCE_GROUP = os.environ.get('DNS_ZONE_RESOURCE_GROUP', 'damienpontifex.com-rg')
DNS_ZONE_NAME = os.environ.get('DNS_ZONE_NAME', 'damienpontifex.com')
REGISTRATION_EMAIL = os.environ.get('REGISTRATION_EMAIL', 'damien.pontifex@gmail.com')

def dns_challenge_handler(authorizations: List[acme.messages.AuthorizationResource], account_key: josepy.JWKRSA) -> Generator[acme.messages.ChallengeResource, None, None]:
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
        """Create the DNS records to respond to challenge
        """

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
class KeyVaultRSAPublicKey(rsa.RSAPublicKey, rsa.RSAPrivateKey):
    def __init__(self, vault_url, key_name, auth):
        self.vault_url = vault_url
        self.key_name = key_name

        self.kvclient = KeyVaultClient(auth)

        key_args = dict(
            vault_base_url=vault_url,
            key_name=key_name)
    
        try:
            self.kv_key = self.kvclient.get_key(**key_args, key_version='')
        except KeyVaultErrorException as e:
            self.kv_key = self.kvclient.create_key(**key_args, kty='RSA', key_size=self.key_size)

    @property
    def key_size(self):
        return 2048

    def encrypt(self, plaintext, padding):
        result = self.kvclient.encrypt(self.vault_url, self.key_name, '', 'RSA', plaintext)
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
        res = self.kvclient.sign(self.vault_url, self.key_name, '', 'RS256', value)
        return res.result


#%%
def get_cert(*domains, use_prod=False, challenge_handler: ChallengeHandler):

    # %%
    """Follow certificate management flow https://tools.ietf.org/html/rfc8555#section-7"""

    # Get directory
    if use_prod:
        server = 'https://acme-v02.api.letsencrypt.org/directory'
        user_key_name = 'acme'
    else:
        server = 'https://acme-staging-v02.api.letsencrypt.org/directory'
        user_key_name = 'acme-staging'


    # %%
    keyvault_auth, subscription_id = get_azure_cli_credentials(resource='https://vault.azure.net')
    key = KeyVaultRSAPublicKey(KEYVAULT_URL, user_key_name, keyvault_auth)

    #%%
    account_key = josepy.JWKRSA(key=key)
    net = acme.client.ClientNetwork(account_key)

    #%%
    directory = messages.Directory.from_json(net.get(server).json())

    #%%
    client = acme.client.ClientV2(directory, net)

    #%%
    new_regr = acme.messages.Registration.from_data(
        key=account_key, email=REGISTRATION_EMAIL, terms_of_service_agreed=True)

    # %%
    # Register or fetch account
    try:
        regr = client.new_account(new_regr)
        print('Created new account')
    except acme.errors.ConflictError as e:
        regr = acme.messages.RegistrationResource(uri=e.location, body=new_regr)
        regr = client.query_registration(regr)
        print('Got existing account')

    # %%
    def _get_csr(domains: List[str], pkey_pem: Optional[str]=None) -> Tuple[str, str]:
        """Get certificate signing request for the given domains using the private key"""
        if pkey_pem is None:
            # Create private key
            pkey = crypto.PKey()
            pkey.generate_key(crypto.TYPE_RSA, 2048)
            pkey_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)
        
        csr_pem = acme.crypto_util.make_csr(pkey_pem, domains)
        return pkey_pem, csr_pem

    # %%
    # Create domain private key and CSR
    pkey_pem, csr_pem = _get_csr(domains)
    # TODO: save pkey_pem in Azure KeyVault or similar so we can call renew

    # Submit order
    orderr: acme.messages.OrderResource = client.new_order(csr_pem)

    # Challenges from order
    # Respond to challenges
    challenges_to_respond_to = list(challenge_handler(orderr.authorizations, account_key))

    #%%
    for dns_challenge in challenges_to_respond_to:
        # Perform challenge
        auth_response = client.answer_challenge(dns_challenge, dns_challenge.chall.response(account_key))

    #%%
    # Poll for status
    # Finalize order
    # Download certificate
    final_order = client.poll_and_finalize(orderr)

    #%%
    # Write out certificate with name matching primary domain
    cert_path = os.path.join(os.getcwd(), '{}.pem'.format(domains[0]))
    with open(cert_path, 'w') as f:
        f.write(final_order.fullchain_pem)


# %%
get_cert('test.damienpontifex.com', 'www.test.damienpontifex.com', 
    use_prod=False, challenge_handler=dns_challenge_handler)