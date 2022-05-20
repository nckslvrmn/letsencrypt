#!/usr/bin/env python3

import os

from os.path import isfile, isdir

import sewer.client

from sewer.crypto import AcmeKey, AcmeAccount
from sewer.dns_providers.route53 import Route53Dns
from yaml import load, FullLoader


def account_key():
    if isfile('account.key'):
        print('existing account key found, using it')
        return False, AcmeKey.from_pem(open('account.key', 'rb').read())
    else:
        print('ACME account key does not exist, creating one')
        account_key = AcmeKey.create('rsa2048')
        with open('account.key', 'wb') as kf:
            kf.write(account_key.to_pem())
        return True, account_key


def cert_priv_key(sanitized):
    print(f'creating new private key in {sanitized}')
    cert_priv_key = AcmeKey.create('rsa2048')
    if not isdir(f'certs/{sanitized}/'):
        os.mkdir(f'certs/{sanitized}/')
    with open(f'certs/{sanitized}/private_key.pem', 'wb') as cpk:
        cpk.write(cert_priv_key.to_pem())
    return cert_priv_key


def main():
    config = load(open('config.yaml', 'r'), Loader=FullLoader)
    new_account, acct_key = account_key()
    for domain in config['domains']:
        print(domain)
        sanitized = domain['domain'].replace('*', 'star').replace('.', '_')
        acme_client = sewer.client.Client(
            account=AcmeAccount(pk=acct_key.pk, key_desc=acct_key.key_desc),
            cert_key=cert_priv_key(sanitized),
            contact_email=config['email'],
            is_new_acct=new_account,
            domain_name=domain['domain'],
            domain_alt_names=domain.get('alt_names'),
            provider=Route53Dns(),
            LOG_LEVEL='DEBUG',
            ACME_AUTH_STATUS_MAX_CHECKS=10
        )
        certificate = acme_client.get_certificate()
        print(f'certficate for {domain} acquired')
        with open(f'certs/{sanitized}/public.crt', 'w') as pc:
            pc.write(certificate)


if __name__ == "__main__":
    main()
