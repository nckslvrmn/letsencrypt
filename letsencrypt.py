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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    Encoding,
    NoEncryption,
    PrivateFormat
)
from cryptography.x509.oid import NameOID
from jwcrypto.jwk import JWK
from yaml import load, FullLoader


def safe_base64(un_encoded_data):
    if isinstance(un_encoded_data, str):
        un_encoded_data = un_encoded_data.encode("utf8")
    r = base64.urlsafe_b64encode(un_encoded_data).rstrip(b"=")
    return r.decode("utf8")


class PyACME:
    def __init__(self):
        self.config = load(open('config.yaml', 'r'), Loader=FullLoader)

        if isfile('account.key'):
            with open('account.key', 'rb') as f:
                self.account_key = load_pem_private_key(f.read(), None)
            self.reg_payload = {"onlyReturnExisting": True}
        else:
            self.account_key = rsa.generate_private_key(65537, 2048)
            self.account_key.write_pem('account.key')
            self.reg_payload = {
                "termsOfServiceAgreed": True,
                "contact": [f"mailto:{self.config['email']}"],
            }

        self.json_wk = JWK.from_pem(self.account_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        ))
        self.acme_jwk = {'kty': 'RSA', 'e': 'AQAB', 'n': self.json_wk.get('n')}

    def __signed_request(self, url, payload=""):
        payload64 = safe_base64(payload)
        response = requests.get('https://acme-v02.api.letsencrypt.org/acme/new-nonce')
        protected = {"alg": 'RS256', "nonce": response.headers["Replay-Nonce"], "url": url}
        if hasattr(self, 'kid'):
            protected['kid'] = self.kid
        elif hasattr(self, 'acme_jwk'):
            protected['jwk'] = self.acme_jwk
        protected64 = safe_base64(json.dumps(protected))
        message = f"{protected64}.{payload64}".encode("utf-8")
        signature64 = safe_base64(self.account_key.sign(message, padding.PKCS1v15(), hashes.SHA256()))
        data = json.dumps({'protected': protected64, 'payload': payload64, 'signature': signature64})
        response = requests.post(url, data=data.encode("utf8"), headers={"Content-Type": "application/jose+json"})
        return response

    def gen_cert_priv_key(self, sanitized):
        self.cert_priv_key = rsa.generate_private_key(65537, 2048)
        if not isdir(f'certs/{sanitized}/'):
            os.mkdir(f'certs/{sanitized}/')
        with open(f'certs/{sanitized}/private_key.pem', 'wb') as cpk:
            cpk.write(self.cert_priv_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            ))

    def gen_csr(self, domain):
        csrb = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, domain['domain'])
            ])
        ).add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(name) for name in list(set([domain['domain']] + domain.get('alt_names')))]
            ),
            critical=False
        )
        self.csr = csrb.sign(self.cert_priv_key, hashes.SHA256())

    def get_account_kid(self):
        response = self.__signed_request(
            'https://acme-v02.api.letsencrypt.org/acme/new-acct',
            payload=json.dumps(self.reg_payload)
        )
        if response.status_code not in [201, 200]:
            raise response.text
        self.kid = response.headers["Location"]

    def request_cert_issuance(self, domain):
        identifiers = []
        for domain_name in list(set([domain['domain']] + domain.get('alt_names'))):
            identifiers.append({"type": "dns", "value": domain_name})
        payload = {"identifiers": identifiers}
        apply_for_cert_issuance_response = self.__signed_request(
            'https://acme-v02.api.letsencrypt.org/acme/new-order',
            payload=json.dumps(payload)
        )
        if apply_for_cert_issuance_response.status_code != 201:
            raise RuntimeError(apply_for_cert_issuance_response.text)
        apply_for_cert_issuance_response_json = apply_for_cert_issuance_response.json()
        self.finalize_url = apply_for_cert_issuance_response_json["finalize"]
        self.authorizations = apply_for_cert_issuance_response_json["authorizations"]

    def get_challenges(self):
        self.challenges = []
        for auth_url in self.authorizations:
            response = self.__signed_request(
                auth_url
            )
            if response.status_code not in [200, 201]:
                raise RuntimeError(response)
            response_json = response.json()

            for chal in response_json["challenges"]:
                acme_header_jwk_json = json.dumps(self.acme_jwk, sort_keys=True)
                acme_thumbprint = safe_base64(sha256(acme_header_jwk_json.encode("utf8")).digest())
                acme_keyauthorization = f"{chal['token']}.{acme_thumbprint}"
                self.challenges.append({
                    "ident_value": response_json["identifier"]["value"],
                    "token": chal["token"],
                    "key_auth": acme_keyauthorization,
                    "dns_challenge": safe_base64(sha256(acme_keyauthorization.encode("utf8")).digest()),
                    "wildcard": response_json.get("wildcard"),
                    "auth_url": auth_url,
                    "chal_url": chal["url"],
                })

    def check_challenge_result(self, auth_url, expected_status):
        number_of_checks = 0
        while True:
            time.sleep(8)
            response = self.__signed_request(auth_url)
            authorization_status = response.json()["status"]
            number_of_checks += 1
            if authorization_status in expected_status:
                break
            if number_of_checks == 3:
                raise RuntimeError('failed after 3 attempts')
        return authorization_status

    def finalize_challenge(self, chal, authorization_status):
        if authorization_status == "pending":
            self.__signed_request(
                chal["chal_url"],
                payload=json.dumps({"keyAuthorization": chal["key_auth"]})
            )

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
                if candidate_labels == target_labels[-len(candidate_labels):]:
                    zones.append((zone["Name"], zone["Id"]))
        zones.sort(key=lambda z: len(z[0]), reverse=True)
        return zones[0][1]

    def set_dns_challenge_record(self, chal, action):
        zone_id = self.__find_zone_id_for_domain(chal['ident_value'])
        changeset = {
            "Comment": "certbot-dns-route53 certificate validation",
            "Changes": [
                {
                    "Action": action,
                    "ResourceRecordSet": {
                        "Name": f"_acme-challenge.{chal['ident_value']}",
                        "Type": "TXT",
                        "TTL": 10,
                        "ResourceRecords": [{"Value": f"\"{chal['dns_challenge']}\""}],
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
        pyacme.gen_csr(domain)
        pyacme.get_account_kid()
        pyacme.request_cert_issuance(domain)
        pyacme.get_challenges()

        acmer53 = ACMERoute53()
        for chal in pyacme.challenges:
            acmer53.set_dns_challenge_record(chal, 'UPSERT')
            authorization_status = pyacme.check_challenge_result(chal['auth_url'], ['pending', 'valid'])
            pyacme.finalize_challenge(chal, authorization_status)
            pyacme.check_challenge_result(chal['auth_url'], ['valid'])
            acmer53.set_dns_challenge_record(chal, 'DELETE')

        pyacme.finalize_cert()
        pyacme.download_cert(sanitized)


if __name__ == "__main__":
    main()
