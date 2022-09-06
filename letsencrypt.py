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
from jwcrypto import jwk
from yaml import load, FullLoader


def safe_base64(un_encoded_data):
    if isinstance(un_encoded_data, str):
        un_encoded_data = un_encoded_data.encode("utf8")
    r = base64.urlsafe_b64encode(un_encoded_data).rstrip(b"=")
    return r.decode("utf8")


def signed_request(url, pk, payload="", jwk=None, kid=None):
    payload64 = safe_base64(payload)
    response = requests.get('https://acme-v02.api.letsencrypt.org/acme/new-nonce')
    protected = {"alg": 'RS256', "nonce": response.headers["Replay-Nonce"], "url": url}
    if jwk is not None:
        protected['jwk'] = jwk
    if kid is not None:
        protected['kid'] = kid
    protected64 = safe_base64(json.dumps(protected))
    message = f"{protected64}.{payload64}".encode("utf-8")
    signature64 = safe_base64(pk.sign(message, padding.PKCS1v15(), hashes.SHA256()))
    data = json.dumps({'protected': protected64, 'payload': payload64, 'signature': signature64})
    response = requests.post(url, data=data.encode("utf8"), headers={"Content-Type": "application/jose+json"})
    return response


def find_zone_id_for_domain(r53, domain):
    paginator = r53.get_paginator("list_hosted_zones")
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


def main():
    config = load(open('config.yaml', 'r'), Loader=FullLoader)

    if isfile('account.key'):
        with open('account.key', 'rb') as f:
            account_key = load_pem_private_key(f.read(), None)
        reg_payload = {"onlyReturnExisting": True}
    else:
        account_key = rsa.generate_private_key(65537, 2048)
        account_key.write_pem('account.key')
        reg_payload = {
            "termsOfServiceAgreed": True,
            "contact": [f"mailto:{config['email']}"],
        }

    json_wk = jwk.JWK.from_pem(account_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    ))
    j = {'kty': 'RSA', 'e': 'AQAB', 'n': json_wk.get('n')}

    for domain in config['domains']:
        sanitized = domain['domain'].replace('*', 'star').replace('.', '_')

        # create and store new cert priv key
        cert_priv_key = rsa.generate_private_key(65537, 2048)
        if not isdir(f'certs/{sanitized}/'):
            os.mkdir(f'certs/{sanitized}/')
        with open(f'certs/{sanitized}/private_key.pem', 'wb') as cpk:
            cpk.write(cert_priv_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            ))

        # make CSR
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
        csr = csrb.sign(cert_priv_key, hashes.SHA256())

        # generate jwk and get kid
        response = signed_request(
            'https://acme-v02.api.letsencrypt.org/acme/new-acct',
            account_key,
            payload=json.dumps(reg_payload),
            jwk=j
        )
        if response.status_code not in [201, 200]:
            raise response.text
        kid = response.headers["Location"]

        # request cert issuance
        identifiers = []
        for domain_name in list(set([domain['domain']] + domain.get('alt_names'))):
            identifiers.append({"type": "dns", "value": domain_name})
        payload = {"identifiers": identifiers}
        apply_for_cert_issuance_response = signed_request(
            'https://acme-v02.api.letsencrypt.org/acme/new-order',
            account_key,
            payload=json.dumps(payload),
            kid=kid
        )
        if apply_for_cert_issuance_response.status_code != 201:
            raise RuntimeError(apply_for_cert_issuance_response.text)
        apply_for_cert_issuance_response_json = apply_for_cert_issuance_response.json()
        finalize_url = apply_for_cert_issuance_response_json["finalize"]
        authorizations = apply_for_cert_issuance_response_json["authorizations"]

        # get authorization information for challenges
        challenges = []
        for auth_url in authorizations:
            response = signed_request(
                auth_url,
                account_key,
                kid=kid
            )
            if response.status_code not in [200, 201]:
                raise RuntimeError(response)
            response_json = response.json()

            for chal in response_json["challenges"]:
                acme_header_jwk_json = json.dumps(j, sort_keys=True)
                acme_thumbprint = safe_base64(sha256(acme_header_jwk_json.encode("utf8")).digest())
                acme_keyauthorization = f"{chal['token']}.{acme_thumbprint}"
                challenges.append({
                    "ident_value": response_json["identifier"]["value"],
                    "token": chal["token"],
                    "key_auth": acme_keyauthorization,
                    "wildcard": response_json.get("wildcard"),
                    "auth_url": auth_url,
                    "chal_url": chal["url"],
                })

        r53 = boto3.client("route53")
        for chal in challenges:
            # set DNS for challenge
            dns_challenge = safe_base64(sha256(chal["key_auth"].encode("utf8")).digest())
            zone_id = find_zone_id_for_domain(r53, chal['ident_value'])
            changeset = {
                "Comment": "certbot-dns-route53 certificate validation",
                "Changes": [
                    {
                        "Action": "UPSERT",
                        "ResourceRecordSet": {
                            "Name": f"_acme-challenge.{chal['ident_value']}",
                            "Type": "TXT",
                            "TTL": 10,
                            "ResourceRecords": [{"Value": f'"{dns_challenge}"'}],
                        },
                    }
                ],
            }
            response = r53.change_resource_record_sets(HostedZoneId=zone_id, ChangeBatch=changeset)
            change_id = response["ChangeInfo"]["Id"]
            while True:
                resp = r53.get_change(Id=change_id)
                if resp["ChangeInfo"]["Status"] == "INSYNC":
                    break
                else:
                    time.sleep(1)

            # check that challenge is pending
            number_of_checks = 0
            while True:
                time.sleep(8)
                response = signed_request(chal["auth_url"], account_key, kid=kid)
                authorization_status = response.json()["status"]
                number_of_checks += 1
                if authorization_status in ["pending", "valid"]:
                    break
                if number_of_checks == 3:
                    raise RuntimeError('failed after 3 attempts')

            # submit finalization request for challenge
            if authorization_status == "pending":
                payload = json.dumps({"keyAuthorization": chal["key_auth"]})
                signed_request(
                    chal["chal_url"],
                    account_key,
                    payload=json.dumps({"keyAuthorization": chal["key_auth"]}),
                    kid=kid,
                )
            number_of_checks = 0
            while True:
                time.sleep(8)
                response = signed_request(
                    chal["auth_url"],
                    account_key,
                    kid=kid,
                )
                authorization_status = response.json()["status"]
                number_of_checks += 1
                if authorization_status in ["valid"]:
                    break
                if number_of_checks == 3:
                    raise RuntimeError('failed after 3 attempts')

            # clean up DNS challenge
            changeset['Changes'][0]['Action'] = 'DELETE'
            response = r53.change_resource_record_sets(HostedZoneId=zone_id, ChangeBatch=changeset)

        # send csr to finalize cert request
        payload = {"csr": safe_base64(csr.public_bytes(Encoding.DER))}
        send_csr_response = signed_request(
            finalize_url,
            account_key,
            payload=json.dumps(payload),
            kid=kid,
        )
        if send_csr_response.status_code not in [200, 201]:
            raise RuntimeError(send_csr_response.text)
        send_csr_response_json = send_csr_response.json()
        certificate_url = send_csr_response_json["certificate"]

        # download signed certificate
        response = signed_request(
            certificate_url,
            account_key,
            kid=kid,
        )
        if response.status_code not in [200, 201]:
            raise ValueError(response.text)
        certificate = response.content.decode("utf-8")
        with open(f'certs/{sanitized}/public.crt', 'w') as pc:
            pc.write(certificate)


if __name__ == "__main__":
    main()
