from typing import Generator, List, Tuple
import acme
import josepy
from azure.common.credentials import get_azure_cli_credentials
from azure.mgmt.dns import DnsManagementClient

# Until azure.identity package is merged with management libraries https://github.com/Azure/azure-sdk-for-python/issues/9310#issuecomment-606893344
from msrest.authentication import BasicTokenAuthentication
class CredentialWrapper(BasicTokenAuthentication):
    def __init__(self, credentials, resource_id="https://management.azure.com/.default"):
        """Create a wrapper. 
        
        Default resource is ARM (syntax of endpoint v2)
        """
        super(CredentialWrapper, self).__init__(None)
        self._credentials = credentials
        self._resource = resource_id

    def set_token(self):
        token = self._credentials.get_token(self._resource)
        self.token = {"access_token": token.token}

    def signed_session(self, session=None):
        self.set_token()
        return super(CredentialWrapper, self).signed_session(session)
        
# if __name__ == "__main__":
#   from azure.identity import DefaultAzureCredential
#   credentials = CredentialWrapper(DefaultAzureCredential())
#   
#   from azure.mgmt.resource import ResourceManagementClient
#   client = ResourceManagementClient(credentials, "<subscription_id>")
#   for rg in client.resource_groups.list():
#         print(rg.name)


def dns_challenge_handler(credential, subscription_id: str, dns_zone_resource_group: str, dns_zone_name: str, authorizations: List[acme.messages.AuthorizationResource], account_key: josepy.JWKRSA) -> Generator[acme.messages.ChallengeResource, None, None]:
    """Extract DNS challenges and ensure they're created in Azure DNS"""

    def _get_dns_challenge(authzr: acme.messages.AuthorizationResource) -> Tuple[acme.challenges.DNS01, str]:
        """Find DNS challenge from authorization challenge options"""
        challenge = next(c for c in authzr.body.challenges if type(c.chall) == acme.challenges.DNS01)
        return challenge, authzr.body.identifier.value

    # Select DNS-01 within offered challenges by the CA server
    dns_challenges = (_get_dns_challenge(auth_resource) for auth_resource in authorizations)

    #%%
    dns_auth = CredentialWrapper(credential)
    # dns_auth, subscription_id = get_azure_cli_credentials()
    dns_client = DnsManagementClient(dns_auth, subscription_id)

    #%%
    # Create the DNS records used for the challenge
    for dns_challenge, url in dns_challenges:
        # Drop the top level domain from the record value
        domain_prefix = '.'.join(url.split('.')[:-2])
        record_set_name = dns_challenge.chall.validation_domain_name(domain_prefix)
        record_set_value = dns_challenge.chall.validation(account_key)

        dns_client.record_sets.create_or_update(
            resource_group_name=dns_zone_resource_group, zone_name=dns_zone_name, 
            relative_record_set_name=record_set_name, record_type='TXT', parameters={
                'ttl': 3600,
                'txtrecords': [
                    { 'value': [record_set_value] }
                ]
            })

        yield dns_challenge
