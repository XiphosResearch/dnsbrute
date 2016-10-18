PYTHON ?= python

all:

docker-run: docker-build
	docker run -ti harryr/dnsbrute

docker-build:
	docker build -t harryr/dnsbrute .

test:
	$(PYTHON) -mdnsbrute --debug -p example.com

lint:
	$(PYTHON) -mpyflakes dnsbrute
	$(PYTHON) -mpylint -d missing-docstring dnsbrute