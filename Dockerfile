FROM alpine:3.18.3
# Dex connectors, such as GitHub and Google logins require root certificates.
# Proper installations should manage those certificates, but it's a bad user
# experience when this doesn't work out of the box.
#
# OpenSSL is required so wget can query HTTPS endpoints for health checking.
RUN apk add --update ca-certificates openssl curl tini

RUN mkdir -p /app/bin
COPY ./bin/linux/amd64/dex-k8s-authenticator /app/bin/dex-k8s-authenticator
COPY html /app/html
COPY templates /app/templates
COPY templates /app/original-templates

# Add any required certs/key by mounting a volume on /certs - Entrypoint will copy them and run update-ca-certificates at startup
RUN mkdir -p /certs

WORKDIR /app

COPY entrypoint.sh /
RUN chmod a+x /entrypoint.sh

ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]

CMD ["--help"]
