PYTHON ?= python

all:

test:
	$(PYTHON) -mdnsbrute --debug -p example.com

lint:
	$(PYTHON) -mpyflakes dnsbrute
	$(PYTHON) -mpylint -d missing-docstring dnsbrute