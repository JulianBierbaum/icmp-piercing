FROM alpine:latest

RUN apk add --no-cache iptables iproute2 bash

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
