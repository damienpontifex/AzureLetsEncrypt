import os
import base64
import logging
import datetime
import functools
from typing import List, Tuple, Optional, Callable

import josepy
from acme import messages, client
import acme

from .key_vault_rsa_key import KeyVaultRSAKey
from .azure_dns import dns_challenge_handler

from azure.identity import DefaultAzureCredential, InteractiveBrowserCredential
from azure.keyvault.certificates import CertificateClient, CertificatePolicy, KeyType, SecretContentType

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

KEYVAULT_URL = os.environ.get('KEYVAULT_URL', 'https://pontivault.vault.azure.net/')
DNS_ZONE_RESOURCE_GROUP = os.environ.get('DNS_ZONE_RESOURCE_GROUP', 'damienpontifex.com-rg')
DNS_ZONE_NAME = os.environ.get('DNS_ZONE_NAME', 'damienpontifex.com')
REGISTRATION_EMAIL = os.environ.get('REGISTRATION_EMAIL', 'damien.pontifex@gmail.com')

challenge_handler = functools.partial(dns_challenge_handler, dns_zone_resource_group=DNS_ZONE_RESOURCE_GROUP, dns_zone_name=DNS_ZONE_NAME)

def create_or_update_cert(kv_cert_name, *domains, use_prod=False):

    # Get directory
    if use_prod:
        directory_url = 'https://acme-v02.api.letsencrypt.org/directory'
        user_key_name = 'acme'
        issuance_period_months = 3
    else:
        directory_url = 'https://acme-staging-v02.api.letsencrypt.org/directory'
        user_key_name = 'acme-staging'
        issuance_period_months = 1

    credential = DefaultAzureCredential()

    cert_client = CertificateClient(vault_url=KEYVAULT_URL, credential=credential)

    #%% 
    key = KeyVaultRSAKey(credential, KEYVAULT_URL, user_key_name)

    account_key = josepy.JWKRSA(key=key)
    client_network = acme.client.ClientNetwork(account_key)

    directory = messages.Directory.from_json(client_network.get(directory_url).json())

    client = acme.client.ClientV2(directory, client_network)

    new_regr = acme.messages.Registration.from_data(
        key=account_key, email=REGISTRATION_EMAIL, terms_of_service_agreed=True)

    # Register or fetch account
    try:
        regr = client.new_account(new_regr)
        logger.info('Created new account')
    except acme.errors.ConflictError as e:
        regr = acme.messages.RegistrationResource(uri=e.location, body=new_regr)
        regr = client.query_registration(regr)
        logger.info('Got existing account')

    cert_policy = CertificatePolicy(
        issuer_name='Unknown',
        subject_name=f'CN={domains[0]}',
        exportable=True,
        key_type=KeyType.rsa,
        key_size=2048,
        content_type=SecretContentType.PKCS12,
        san_dns_names=domains[1:] if len(domains) > 1 else [],
        validity_in_months=issuance_period_months
    )

    cert_op = cert_client.begin_create_certificate(name=kv_cert_name, policy=cert_policy)
    # cert_op = kvclient.create_certificate(KEYVAULT_URL, certificate_name=kv_cert_name, certificate_policy=cert_policy)
    cert_op_res = cert_op.result()
    cert_op_r = cert_client.get_certificate_operation(kv_cert_name)

    logger.info('Created certificate request in key vault')

    # Wrap with header and footer for pem to show certificate request
    csr_pem = "-----BEGIN CERTIFICATE REQUEST-----\n" + base64.b64encode(cert_op_r.csr).decode() + "\n-----END CERTIFICATE REQUEST-----\n"

    # Submit order
    order_resource = client.new_order(csr_pem)
    logger.info('Submitted order')

    # Challenges from order
    # Respond to challenges
    challenges_to_respond_to = list(challenge_handler(authorizations=order_resource.authorizations, account_key=account_key))

    for dns_challenge in challenges_to_respond_to:
        # Perform challenge
        auth_response = client.answer_challenge(dns_challenge, dns_challenge.chall.response(account_key))

    logger.info('Answered challenges')

    # Poll for status
    # Finalize order
    # Download certificate
    final_order = client.poll_and_finalize(order_resource)

    logger.info('Finalised order')

    # Strip header and footer of BEGIN/END CERTIFICATE
    # with open('cert.pem', 'w') as f:
    #     f.write(final_order.fullchain_pem)

    certificate_vals = [val.replace('\n', '').encode() for val in final_order.fullchain_pem.split('-----') 
                        if 'CERTIFICATE' not in val and len(val.replace('\n', '')) != 0]

    cert_client.merge_certificate(name=kv_cert_name, x509_certificates=certificate_vals)

    logger.info('Merged certificate back to key vault')

if __name__ == '__main__':
    from .certs import certs
    for cert_name, domains in certs.items():
        create_or_update_cert(cert_name, *domains, use_prod=False)