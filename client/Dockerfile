FROM python:latest

RUN apt-get update && apt-get install -y iproute2 iputils-ping

RUN pip install --no-cache-dir scapy

COPY attack.py /attack.py
RUN chmod +x /attack.py

CMD ["tail", "-f", "/dev/null"]
