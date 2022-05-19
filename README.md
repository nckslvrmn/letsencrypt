# letsencrypt

This script uses [sewer](https://github.com/komuw/sewer/) to interact with the letsencrypt ACME APIs to request and download new certs. Though sewer can handle many DNS providers, this script uses the route53 provider.

## dependencies

This script requires python 3.7+ and `pip` for dependent packages. To install dependent packages run:
```
pip install -r requirements.txt
```

## configuration

This script takes a `config.yaml` that can be copied from the `config.yaml.example` as a starting point. It supports both wildcard domains and single domains. Note that wildcards need a list of alt names that consists of the base domain (e.g. if the wildcard is `*.coolwebsite.io` the base domain would be `coolwebsite.io`).

To tell the script which AWS account and region to use for route53 DNS challenge record management, specify any of the environment variables the AWS SDK supports. For more on that, check the [documentation](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html).

## running

to run:
```
AWS_ENV_VARS ./certs.py
```
