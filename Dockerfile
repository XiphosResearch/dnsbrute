FROM jfloff/alpine-python:2.7-onbuild

COPY . /root/dnsbrute-py/

WORKDIR /root/dnsbrute-py

ENTRYPOINT ["/usr/bin/python", "-mdnsbrute"]