# Every target needs only bash, docker and curl on the host: the tools run in
# pinned container images, so a local run behaves like CI.

SHELL := /bin/bash
TESTS := $(filter-out tests/kubernetes-e2e.sh,$(sort $(wildcard tests/*.sh)))

# Pinned by digest, with the tag it belonged to, exactly like the pins in
# tests/: a tag is a mutable pointer, and tests/cicd.sh checks this line.
MARKDOWNLINT_IMAGE := davidanson/markdownlint-cli2@sha256:d5f3f3f04b2e285dcbcdcd13b4454d119e273e3c393a9dabd163dba4abad526d # davidanson/markdownlint-cli2:v0.23.3

.PHONY: help test e2e lint all

help:
	@echo "make test   validate every baseline file (tests/*.sh, no cluster)"
	@echo "make e2e    Kubernetes end-to-end checks on a throwaway kind cluster"
	@echo "make lint   markdownlint on all guides"
	@echo "make all    lint + test + e2e"

test:
	@set -e; for t in $(TESTS); do echo "==> $$t"; bash "$$t"; done

e2e:
	bash tests/kubernetes-e2e.sh

lint:
	docker run --rm -v "$(CURDIR)":/w -w /w $(MARKDOWNLINT_IMAGE) "**/*.md"

all: lint test e2e
