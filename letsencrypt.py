#!/usr/bin/env python3

import base64
import json
import os
import time

import boto3
import requests

from hashlib import sha256
from os.path import isfile, isdir

from cryptography import x509
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, NoEncryption, PrivateFormat
from cryptography.utils import int_to_bytes
from yaml import load, FullLoader


def safe_base64(b):
    return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")


class PyACME:
    def __init__(self):
        self.config = load(open('config.yaml', 'r'), Loader=FullLoader)

        if isfile('account.key'):
            with open('account.key', 'rb') as f:
                self.account_key = load_pem_private_key(f.read(), None)
            self.reg_payload = {"onlyReturnExisting": True}
        else:
            self.account_key = generate_private_key(65537, 2048)
            with open('account.key', 'wb') as f:
                f.write(self.account_key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()))
            self.reg_payload = {
                "termsOfServiceAgreed": True,
                "contact": [f"mailto:{self.config['email']}"],
            }

        pn = self.account_key.public_key().public_numbers()
        self.acme_jwk = {'kty': 'RSA', 'e': safe_base64(int_to_bytes(pn.e)), 'n': safe_base64(int_to_bytes(pn.n))}
        self.json_jwk = json.dumps(self.acme_jwk, sort_keys=True, separators=(',', ':'))
        self.acme_thumbprint = safe_base64(sha256(self.json_jwk.encode("utf8")).digest())

    def __signed_request(self, url, payload=""):
        payload64 = safe_base64(payload.encode('utf-8'))
        response = requests.get('https://acme-v02.api.letsencrypt.org/acme/new-nonce')
        protected = {"alg": 'RS256', "nonce": response.headers["Replay-Nonce"], "url": url}
        if hasattr(self, 'kid'):
            protected['kid'] = self.kid
        elif hasattr(self, 'acme_jwk'):
            protected['jwk'] = self.acme_jwk
        protected64 = safe_base64(json.dumps(protected).encode('utf-8'))
        message = f"{protected64}.{payload64}".encode("utf-8")
        signature64 = safe_base64(self.account_key.sign(message, PKCS1v15(), SHA256()))
        data = json.dumps({'protected': protected64, 'payload': payload64, 'signature': signature64})
        response = requests.post(url, data=data.encode("utf8"), headers={"Content-Type": "application/jose+json"})
        return response

    def gen_cert_priv_key(self, sanitized):
        self.cert_priv_key = generate_private_key(65537, 2048)
        if not isdir(f'certs/{sanitized}/'):
            os.mkdir(f'certs/{sanitized}/')
        with open(f'certs/{sanitized}/private_key.pem', 'wb') as cpk:
            cpk.write(self.cert_priv_key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()))

    def gen_csr(self, domain):
        csrb = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, domain['domain'])]))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(name) for name in list(set([domain['domain']] + domain.get('alt_names', [])))]), critical=False
            )
        )
        self.csr = csrb.sign(self.cert_priv_key, SHA256())

    def get_account_kid(self):
        response = self.__signed_request('https://acme-v02.api.letsencrypt.org/acme/new-acct', payload=json.dumps(self.reg_payload))
        if response.status_code not in [201, 200]:
            raise response.text
        self.kid = response.headers["Location"]

    def request_cert_issuance(self, domain):
        identifiers = []
        for domain_name in list(set([domain['domain']] + domain.get('alt_names', []))):
            identifiers.append({"type": "dns", "value": domain_name})
        payload = {"identifiers": identifiers}
        apply_for_cert_issuance_response = self.__signed_request('https://acme-v02.api.letsencrypt.org/acme/new-order', payload=json.dumps(payload))
        if apply_for_cert_issuance_response.status_code != 201:
            raise RuntimeError(apply_for_cert_issuance_response.text)
        apply_for_cert_issuance_response_json = apply_for_cert_issuance_response.json()
        self.finalize_url = apply_for_cert_issuance_response_json["finalize"]
        self.authorizations = apply_for_cert_issuance_response_json["authorizations"]

    def get_challenges(self):
        self.challenges = {}
        for auth_url in self.authorizations:
            response = self.__signed_request(auth_url)
            if response.status_code not in [200, 201]:
                raise RuntimeError(response)
            response_json = response.json()

            for chal in response_json["challenges"]:
                acme_keyauthorization = f"{chal['token']}.{self.acme_thumbprint}"
                if chal['type'] != 'dns-01':
                    continue
                safe_ident = response_json["identifier"]["value"].replace('.', '_')
                dns_challenge = safe_base64(sha256(acme_keyauthorization.encode("utf8")).digest())
                if self.challenges.get(safe_ident) is None:
                    self.challenges[safe_ident] = []
                self.challenges[safe_ident].append(
                    {
                        "ident_value": response_json["identifier"]["value"],
                        "token": chal["token"],
                        "key_auth": acme_keyauthorization,
                        "dns_challenge": f'"{dns_challenge}"',
                        "wildcard": response_json.get("wildcard"),
                        "auth_url": auth_url,
                        "chal_url": chal["url"],
                    }
                )

    def check_challenge_result(self, auth_url, expected_status):
        number_of_checks = 0
        while True:
            time.sleep(5)
            response = self.__signed_request(auth_url)
            authorization_status = response.json()["status"]
            number_of_checks += 1
            if authorization_status in expected_status:
                break
            if number_of_checks == 6:
                raise RuntimeError('failed after 3 attempts')
        return authorization_status

    def finalize_challenge(self, chal, authorization_status):
        if authorization_status == "pending":
            self.__signed_request(chal["chal_url"], payload=json.dumps({"keyAuthorization": chal["key_auth"]}))

    def finalize_cert(self):
        payload = {"csr": safe_base64(self.csr.public_bytes(Encoding.DER))}
        send_csr_response = self.__signed_request(
            self.finalize_url,
            payload=json.dumps(payload),
        )
        if send_csr_response.status_code not in [200, 201]:
            raise RuntimeError(send_csr_response.text)
        send_csr_response_json = send_csr_response.json()
        self.certificate_url = send_csr_response_json["certificate"]

    def download_cert(self, sanitized):
        response = self.__signed_request(self.certificate_url)
        if response.status_code not in [200, 201]:
            raise ValueError(response.text)
        certificate = response.content.decode("utf-8")
        with open(f'certs/{sanitized}/public.crt', 'w') as pc:
            pc.write(certificate)


class ACMERoute53:
    def __init__(self):
        self.r53 = boto3.client("route53")

    def __find_zone_id_for_domain(self, domain):
        paginator = self.r53.get_paginator("list_hosted_zones")
        zones = []
        target_labels = domain.rstrip(".").split(".")
        for page in paginator.paginate():
            for zone in page["HostedZones"]:
                if zone["Config"]["PrivateZone"]:
                    continue
                candidate_labels = zone["Name"].rstrip(".").split(".")
                if candidate_labels == target_labels[-len(candidate_labels) :]:
                    zones.append((zone["Name"], zone["Id"]))
        zones.sort(key=lambda z: len(z[0]), reverse=True)
        return zones[0][1]

    def set_dns_challenge_record(self, ident, action):
        zone_id = self.__find_zone_id_for_domain(ident[0]['ident_value'])
        changeset = {
            "Comment": "certbot-dns-route53 certificate validation",
            "Changes": [
                {
                    "Action": action,
                    "ResourceRecordSet": {
                        "Name": f"_acme-challenge.{ident[0]['ident_value']}",
                        "Type": "TXT",
                        "TTL": 10,
                        "ResourceRecords": [{"Value": chal['dns_challenge']} for chal in ident],
                    },
                }
            ],
        }
        response = self.r53.change_resource_record_sets(HostedZoneId=zone_id, ChangeBatch=changeset)
        change_id = response["ChangeInfo"]["Id"]
        self.__wait_for_change(change_id)

    def __wait_for_change(self, change_id):
        while True:
            resp = self.r53.get_change(Id=change_id)
            if resp["ChangeInfo"]["Status"] == "INSYNC":
                break
            else:
                time.sleep(1)


def main():
    pyacme = PyACME()

    for domain in pyacme.config['domains']:
        sanitized = domain['domain'].replace('*', 'star').replace('.', '_')
        pyacme.gen_cert_priv_key(sanitized)
        print('RSA private key generated')
        pyacme.gen_csr(domain)
        print('certificat signing request generated')
        pyacme.get_account_kid()
        print('account id retrieved from ACME')
        pyacme.request_cert_issuance(domain)
        print('certificate signing request initiated with ACME')
        pyacme.get_challenges()
        print('DNS challenges received from ACME')

        acmer53 = ACMERoute53()
        for ident in pyacme.challenges:
            print('setting DNS challenge records in Route 53')
            acmer53.set_dns_challenge_record(pyacme.challenges[ident], 'UPSERT')
            for chal in pyacme.challenges[ident]:
                print(f'checking DNS challenge result for {chal["auth_url"]}')
                authorization_status = pyacme.check_challenge_result(chal['auth_url'], ['pending', 'valid'])
                pyacme.finalize_challenge(chal, authorization_status)
                pyacme.check_challenge_result(chal['auth_url'], ['valid'])
                print(f'DNS challenge completed for {chal["auth_url"]}')
            print('deleting DNS challenge records in Route 53')
            acmer53.set_dns_challenge_record(pyacme.challenges[ident], 'DELETE')

        pyacme.finalize_cert()
        print('finalized certificate signing request')
        pyacme.download_cert(sanitized)
        print('finalized certificate downloaded')


if __name__ == "__main__":
    main()
