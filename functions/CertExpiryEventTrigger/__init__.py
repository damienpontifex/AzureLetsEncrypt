import json
import logging

import azure.functions as func
from .azure_keyvault_letsencrypt import create_or_update_cert
from .certs import certs

def main(event: func.EventGridEvent):
    """Respond to Event Grid events from Key Vault for:
        Microsoft.KeyVault.CertificateNearExpiry",
        Microsoft.KeyVault.CertificateExpired
    """

    result = json.dumps({
        'id': event.id,
        'data': event.get_json(),
        'topic': event.topic,
        'subject': event.subject,
        'event_type': event.event_type,
    })

    logging.info('Python EventGrid trigger processed an event: %s', result)

    # TODO: Actually renew certificate - have to look up schema of event.get_json() object
    # certificate_name = event.get_json()['name']
    # domains = certs[certificate_name]
    # create_or_update_cert(certificate_name, *domains)