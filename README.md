# SOAR Hello World sample API

This project contains a simple REST API that is used by the HelloWorld integration of Cortex XSOAR (formerly known as Demisto).

This API can easily be deployed using the `serverless` framework ([https://serverless.com]).

The only configuration options are the API key you want to use, and the FQDN you want your service to reply to (you will need that domain to be configured in Route53 and have an AWS Certificate for it).

The configuration can be specified in the `secrets.yml` file:
```
API_KEY: "YOUR_API_KEY"
FQDN: "your.domain.tld"
```

This code is not supported, but feel free to open Issues here on GitHub for questions!
