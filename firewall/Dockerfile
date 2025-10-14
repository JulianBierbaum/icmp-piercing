FROM ubuntu:latest

RUN apt-get update && apt-get install -y ufw iproute2

COPY entrypoint.sh /entrypoint.sh

RUN echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

RUN chmod +x /entrypoint.sh


CMD ["/entrypoint.sh"]