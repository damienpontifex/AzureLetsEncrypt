from typing import Generator, List, Tuple
import acme
import josepy
from azure.common.credentials import get_azure_cli_credentials
from azure.mgmt.dns import DnsManagementClient

def dns_challenge_handler(dns_zone_resource_group: str, dns_zone_name: str, authorizations: List[acme.messages.AuthorizationResource], account_key: josepy.JWKRSA) -> Generator[acme.messages.ChallengeResource, None, None]:
    """Extract DNS challenges and ensure they're created in Azure DNS"""

    def _get_dns_challenge(authzr: acme.messages.AuthorizationResource) -> Tuple[acme.challenges.DNS01, str]:
        """Find DNS challenge from authorization challenge options"""
        challenge = next(c for c in authzr.body.challenges if type(c.chall) == acme.challenges.DNS01)
        return challenge, authzr.body.identifier.value

    # Select DNS-01 within offered challenges by the CA server
    dns_challenges = (_get_dns_challenge(auth_resource) for auth_resource in authorizations)

    #%%
    dns_auth, subscription_id = get_azure_cli_credentials()

    def _create_dns_records(txt_record_name, txt_record_value, auth, subscription_id):
        """Create the DNS records to respond to challenge"""

        dns_client = DnsManagementClient(auth, subscription_id)
        
        dns_client.record_sets.create_or_update(
            resource_group_name=dns_zone_resource_group, zone_name=dns_zone_name, 
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
