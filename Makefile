# Docker-driven Go targets — no host Go toolchain required.
# Everything runs inside the official golang image with this dir mounted.

GO_IMAGE ?= golang:1.24
DOCKER_RUN = docker run --rm -v "$(CURDIR)":/src -w /src -e GOFLAGS=-mod=mod $(GO_IMAGE)

OAPI_CODEGEN ?= github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.4.1
PY_IMAGE ?= python:3-alpine
PY_RUN = docker run --rm -v "$(CURDIR)":/src -w /src $(PY_IMAGE)

.PHONY: build test vet fmt tidy check generate normalize

# Normalize FastAPI's OpenAPI 3.1 specs into oapi-codegen-friendly 3.0.
# (oapi-codegen v2 can't parse 3.1's anyOf:[T,null] nullable idiom.)
normalize:
	$(PY_RUN) python tools/normalize_openapi.py specs/automation.json specs/automation.norm.json

# Generate typed per-service clients from the normalized specs.
generate: normalize
	$(DOCKER_RUN) sh -c "cd services/automation && go run $(OAPI_CODEGEN) -config config.yaml ../../specs/automation.norm.json"
	$(DOCKER_RUN) go mod tidy

build:
	$(DOCKER_RUN) go build ./...

test:
	$(DOCKER_RUN) go test ./... -count=1

vet:
	$(DOCKER_RUN) go vet ./...

fmt:
	$(DOCKER_RUN) gofmt -l -w .

tidy:
	$(DOCKER_RUN) go mod tidy

check: vet test
