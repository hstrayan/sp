FROM alpine:3.4
MAINTAINER Harish S

ENV VAULT_ADDR=http://vault:8200
ENV VAULT_TOKEN=myroot

RUN apk add --update curl && \
    rm -rf /var/cache/apk/*
# add credentials for rolodex
# if more credentials need to be added/deleted etc, will move this to a sh script    
ENTRYPOINT /usr/bin/curl \
    -H "X-Vault-Token: myroot" \
    -H "Content-Type: application/json" \
    -X POST \
    -d '{"value":"secret","username":"uid=admin,ou=system"}' \
    http://vault:8200/v1/secret/credentials
    
    