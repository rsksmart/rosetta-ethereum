.PHONY: deps build run lint run-mainnet-online run-mainnet-offline run-testnet-online \
	run-testnet-offline check-comments add-license check-license shorten-lines \
	spellcheck salus build-local format check-format test coverage coverage-local \
	update-bootstrap-balances mocks

ADDLICENSE_CMD=go run github.com/google/addlicense
ADDLICENCE_SCRIPT=${ADDLICENSE_CMD} -c "Coinbase, Inc." -l "apache" -v
SPELLCHECK_CMD=go run github.com/client9/misspell/cmd/misspell
GOLINES_CMD=go run github.com/segmentio/golines
GOLINT_CMD=go run golang.org/x/lint/golint
GOVERALLS_CMD=go run github.com/mattn/goveralls
GOIMPORTS_CMD=go run golang.org/x/tools/cmd/goimports
GO_PACKAGES=./services/... ./cmd/... ./configuration/... ./ethereum/... 
GO_FOLDERS=$(shell echo ${GO_PACKAGES} | sed -e "s/\.\///g" | sed -e "s/\/\.\.\.//g")
TEST_SCRIPT=go test ${GO_PACKAGES}
LINT_SETTINGS=golint,misspell,gocyclo,gocritic,whitespace,goconst,gocognit,bodyclose,unconvert,lll,unparam
PWD=$(shell pwd)
NOFILE=100000

deps:
	go get ./...

test:
	${TEST_SCRIPT}

build:
	docker build -t rosetta-rsk:latest https://github.com/rsksmart/rosetta-rsk.git

build-local:
	docker build -t rosetta-rsk:latest .

build-release:
	# make sure to always set version with vX.X.X
	docker build -t rosetta-rsk:$(version) .;
	docker save rosetta-rsk:$(version) | gzip > rosetta-rsk-$(version).tar.gz;

run-mainnet-online:
	docker run -d --rm --ulimit "nofile=${NOFILE}:${NOFILE}" -v "${PWD}/rsk-data:/data" -e "MODE=ONLINE" -e "NETWORK=MAINNET" -e "PORT=8080" -p 8080:8080 -p 30303:30303 rosetta-rsk:latest

run-mainnet-offline:
	docker run -d --rm -e "MODE=OFFLINE" -e "NETWORK=MAINNET" -e "PORT=8081" -p 8081:8081 rosetta-rsk:latest

run-testnet-online:
	docker run -d --rm --ulimit "nofile=${NOFILE}:${NOFILE}" -v "${PWD}/rsk-data:/data" -e "MODE=ONLINE" -e "NETWORK=TESTNET" -e "PORT=8080" -p 8080:8080 -p 30303:30303 rosetta-rsk:latest

run-testnet-offline:
	docker run -d --rm -e "MODE=OFFLINE" -e "NETWORK=TESTNET" -e "PORT=8081" -p 8081:8081 rosetta-rsk:latest

run-mainnet-remote:
	docker run -d --rm --ulimit "nofile=${NOFILE}:${NOFILE}" -e "MODE=ONLINE" -e "NETWORK=MAINNET" -e "PORT=8080" -e "RSKJ=$(rskj)" -p 8080:8080 -p 30303:30303 rosetta-rsk:latest

run-testnet-remote:
	docker run -d --rm --ulimit "nofile=${NOFILE}:${NOFILE}" -e "MODE=ONLINE" -e "NETWORK=TESTNET" -e "PORT=8080" -e "RSKJ=$(rskj)" -p 8080:8080 -p 30303:30303 rosetta-rsk:latest

check-comments:
	${GOLINT_CMD} -set_exit_status ${GO_FOLDERS} .

lint: | check-comments
	golangci-lint run --timeout 2m0s -v -E ${LINT_SETTINGS},gomnd

add-license:
	${ADDLICENCE_SCRIPT} .

check-license:
	${ADDLICENCE_SCRIPT} -check .

shorten-lines:
	${GOLINES_CMD} -w --shorten-comments ${GO_FOLDERS} .

format:
	gofmt -s -w -l .
	${GOIMPORTS_CMD} -w .

check-format:
	! gofmt -s -l . | read
	! ${GOIMPORTS_CMD} -l . | read

salus:
	docker run --rm -t -v ${PWD}:/home/repo coinbase/salus

spellcheck:
	${SPELLCHECK_CMD} -error .

coverage:	
	if [ "${COVERALLS_TOKEN}" ]; then ${TEST_SCRIPT} -coverprofile=c.out -covermode=count; ${GOVERALLS_CMD} -coverprofile=c.out -repotoken ${COVERALLS_TOKEN}; fi

coverage-local:
	${TEST_SCRIPT} -cover

mocks:
	rm -rf mocks;
	mockery --dir services --all --case underscore --outpkg services --output mocks/services;
	mockery --dir ethereum --all --case underscore --outpkg ethereum --output mocks/ethereum;
	${ADDLICENCE_SCRIPT} .;
