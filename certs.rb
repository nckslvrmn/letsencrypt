#!/usr/bin/env ruby

require 'acme-client'
require 'aws-sdk-acm'
require 'aws-sdk-route53'
require 'openssl'
require 'yaml'

def set_challenge_record(r53, challenge, domain, zone_id)
  puts "[#{domain}] - DNS updating record for challenge (#{challenge.record_content})"
  r53.change_resource_record_sets(
    change_batch: {
      changes: [{
        action: 'UPSERT',
        resource_record_set: {
          name: "#{challenge.record_name}.#{domain}",
          resource_records: [{
            value: "\"#{challenge.record_content}\""
          }],
          ttl: 60,
          type: challenge.record_type
        }
      }],
      comment: 'dns challenge for ssl'
    },
    hosted_zone_id: zone_id
  )
  sleep(60)
end

def acme_client(kid)
  private_key = OpenSSL::PKey::RSA.new(File.read('account.key'))
  jwk = Acme::Client::JWK::RSA.new(private_key)
  Acme::Client.new(
    jwk: jwk,
    directory: 'https://acme-v02.api.letsencrypt.org/directory',
    kid: kid
  )
end

def complete_challenge(r53, challenge, domain_name, options)
  set_challenge_record(r53, challenge, domain_name, options['zone_id'])
  puts "[#{domain_name}] - checking for challenge completion"
  challenge.request_validation
  while challenge.status != 'valid'
    puts "[#{domain_name}] - waiting for challenge completion"
    sleep(2)
    challenge.reload
  end
  puts "[#{domain_name}] - challenge completed"
end

def create_certificate(domain_name, order, names)
  ssl_private_key = OpenSSL::PKey::RSA.new(2048)
  csr = Acme::Client::CertificateRequest.new(
    private_key: ssl_private_key,
    common_name: domain_name,
    names: names
  )
  order.finalize(csr: csr)
  puts "[#{domain_name}] - certificate request completed"
  write_certs(domain_name, ssl_private_key, order)
end

def write_certs(domain_name, ssl_private_key, order)
  Dir.mkdir("certs/#{domain_name}") unless File.directory?("certs/#{domain_name}")
  File.write("certs/#{domain_name}/private.pem", ssl_private_key.to_s)
  File.write("certs/#{domain_name}/public.crt", order.certificate)
  puts "[#{domain_name}] - certificates written to disk"
end

def main
  config = YAML.load_file('config.yaml')
  r53 = Aws::Route53::Client.new(region: 'us-east-1')

  config['domains'].each do |domain_name, options|
    client = acme_client(config['kid'])
    puts "[#{domain_name}] - client acquired"

    names = options['wildcard'] ? [domain_name, "*.#{domain_name}"] : [domain_name]
    order = client.new_order(identifiers: names)
    puts "[#{domain_name}] - order started"

    order.authorizations.each do |challenge|
      complete_challenge(r53, challenge.dns, domain_name, options)
    end

    create_certificate(domain_name, order, names)
  end
end

main
