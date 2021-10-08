#!/usr/bin/env ruby

require 'acme-client'
require 'openssl'
require 'yaml'

config = YAML.load_file('config.yaml')
private_key = OpenSSL::PKey::RSA.new(2048)
client = Acme::Client.new(private_key: private_key, directory: 'https://acme-v02.api.letsencrypt.org/directory')
account = client.new_account(contact: "mailto:#{config['email']}", terms_of_service_agreed: true)
config['kid'] = account.kid
File.write('config.yaml', config.to_yaml)
File.write('account.key', private_key.to_pem)
