# Every target needs only bash, docker and curl on the host: the tools run in
# pinned container images, so a local run behaves like CI.

SHELL := /bin/bash
TESTS := $(filter-out tests/kubernetes-e2e.sh,$(sort $(wildcard tests/*.sh)))

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
	docker run --rm -v "$(CURDIR)":/w -w /w davidanson/markdownlint-cli2:v0.23.3 "**/*.md"

all: lint test e2e
