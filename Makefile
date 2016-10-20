PYTHON ?= python
DOCKERTAG ?= harryr/dnsbrute

all:

docker-run: docker-build
	docker run -ti $(DOCKERTAG)

docker-build:
	docker build -t $(DOCKERTAG) .

test:
	$(PYTHON) -mdnsbrute --debug -p example.com

lint:
	$(PYTHON) -mpyflakes dnsbrute
	$(PYTHON) -mpylint -d missing-docstring -r n dnsbrute

clean:
	find ./ -name '*.pyc' -exec rm -f '{}' ';'
