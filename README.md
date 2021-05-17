<p align="center">
  <a href="https://www.rosetta-api.org">
    <img width="90%" alt="Rosetta" src="https://www.rosetta-api.org/img/rosetta_header.png">
  </a>
</p>
<h3 align="center">
   Rosetta RSK
</h3>
<p align="center">
  <a href="https://circleci.com/gh/rsksmart/rosetta-rsk/tree/master"><img src="https://circleci.com/gh/coinbase/rosetta-ethereum/tree/master.svg?style=shield" /></a>
  <a href="https://coveralls.io/github/rsksmart/rosetta-rsk"><img src="https://coveralls.io/repos/github/rsksmart/rosetta-rsk/badge.svg" /></a>
  <a href="https://goreportcard.com/report/github.com/rsksmart/rosetta-rsk"><img src="https://goreportcard.com/badge/github.com/rsksmart/rosetta-rsk" /></a>
  <a href="https://github.com/rsksmart/rosetta-rsk/blob/master/LICENSE.txt"><img src="https://img.shields.io/github/license/rsksmart/rosetta-rsk.svg" /></a>
  <a href="https://pkg.go.dev/github.com/rsksmart/rosetta-rsk?tab=overview"><img src="https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=shield" /></a>
</p>

## Overview
`rosetta-rsk` provides a WIP reference implementation of the Rosetta API for
RSK in Golang. If you haven't heard of the Rosetta API, you can find more
information [here](https://rosetta-api.org).

## Features
* Comprehensive tracking of all rBTC balance changes
* Stateless, offline, curve-based transaction construction (with address checksum validation)
* Idempotent access to all transaction traces and receipts

## Usage
As specified in the [Rosetta API Principles](https://www.rosetta-api.org/docs/automated_deployment.html),
all Rosetta implementations must be deployable via Docker and support running via either an
[`online` or `offline` mode](https://www.rosetta-api.org/docs/node_deployment.html#multiple-modes).

**YOU MUST INSTALL DOCKER FOR THE FOLLOWING INSTRUCTIONS TO WORK. YOU CAN DOWNLOAD
DOCKER [HERE](https://www.docker.com/get-started).**

### Install
Running the following commands will create a Docker image called `rosetta-rsk:latest`.

#### From GitHub
To download the pre-built Docker image from the latest release, run:
```text
curl -sSfL https://raw.githubusercontent.com/rsksmart/rosetta-rsk/master/install.sh | sh -s
```

#### From Source
After cloning this repository, run:
```text
make build-local
```

### Run
Running the following commands will start a Docker container in
[detached mode](https://docs.docker.com/engine/reference/run/#detached--d) with
a data directory at `<working directory>/rsk-data` and the Rosetta API accessible
at port `8080`.

_It is possible to run `rosetta-rsk` using a remote node by adding
`-e "GETH=<node url>"` to any online command._

#### Mainnet:Online
```text
docker run -d --rm --ulimit "nofile=100000:100000" -v "$(pwd)/rsk-data:/data" -e "MODE=ONLINE" -e "NETWORK=MAINNET" -e "PORT=8080" -p 8080:8080 -p 30303:30303 rosetta-rsk:latest
```
_If you cloned the repository, you can run `make run-mainnet-online`._

#### Mainnet:Online (Remote)
```text
docker run -d --rm --ulimit "nofile=100000:100000" -e "MODE=ONLINE" -e "NETWORK=MAINNET" -e "PORT=8080" -e "GETH=<NODE URL>" -p 8080:8080 -p 30303:30303 rosetta-rsk:latest
```
_If you cloned the repository, you can run `make run-mainnet-remote geth=<NODE URL>`._

#### Mainnet:Offline
```text
docker run -d --rm -e "MODE=OFFLINE" -e "NETWORK=MAINNET" -e "PORT=8081" -p 8081:8081 rosetta-rsk:latest
```
_If you cloned the repository, you can run `make run-mainnet-offline`._

#### Testnet:Online
```text
docker run -d --rm --ulimit "nofile=100000:100000" -v "$(pwd)/rsk-data:/data" -e "MODE=ONLINE" -e "NETWORK=TESTNET" -e "PORT=8080" -p 8080:8080 -p 30303:30303 rosetta-rsk:latest
```
_If you cloned the repository, you can run `make run-testnet-online`._

#### Testnet:Online (Remote)
```text
docker run -d --rm --ulimit "nofile=100000:100000" -e "MODE=ONLINE" -e "NETWORK=TESTNET" -e "PORT=8080" -e "GETH=<NODE URL>" -p 8080:8080 -p 30303:30303 rosetta-rsk:latest
```
_If you cloned the repository, you can run `make run-testnet-remote geth=<NODE URL>`._

#### Testnet:Offline
```text
docker run -d --rm -e "MODE=OFFLINE" -e "NETWORK=TESTNET" -e "PORT=8081" -p 8081:8081 rosetta-rsk:latest
```
_If you cloned the repository, you can run `make run-testnet-offline`._

#### Running in Goland

Assuming you have a RSK node running in your own machine at port 4444, you could import the following Run Configuration and run it directly (or even debug it):

```xml
<component name="ProjectRunConfigurationManager">
  <configuration default="false" name="Development localhost node" type="GoApplicationRunConfiguration" factoryName="Go Application">
    <module name="rosetta-rsk" />
    <working_directory value="$PROJECT_DIR$" />
    <parameters value="run" />
    <envs>
      <env name="MODE" value="ONLINE" />
      <env name="NETWORK" value="MAINNET" />
      <env name="PORT" value="8080" />
      <env name="GETH" value="http://localhost:4444" />
    </envs>
    <kind value="PACKAGE" />
    <package value="github.com/rsksmart/rosetta-rsk" />
    <directory value="$PROJECT_DIR$" />
    <filePath value="$PROJECT_DIR$/main.go" />
    <method v="2" />
  </configuration>
</component>
```

## System Requirements
`rosetta-ethereum` (the origin of this fork) has been tested on an [AWS c5.2xlarge instance](https://aws.amazon.com/ec2/instance-types/c5).
This instance type has 8 vCPU and 16 GB of RAM. If you use a computer with less than 16 GB of RAM,
it is possible that `rosetta-rsk` will exit with an OOM error.

### Recommended OS Settings
To increase the load `rosetta-rsk` can handle, it is recommended to tune your OS
settings to allow for more connections. On a linux-based OS, you can run the following
commands ([source](http://www.tweaked.io/guide/kernel)):
```text
sysctl -w net.ipv4.tcp_tw_reuse=1
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
sysctl -w net.ipv4.tcp_max_syn_backlog=10000
sysctl -w net.core.somaxconn=10000
sysctl -p (when done)
```
_We have not tested `rosetta-rsk` with `net.ipv4.tcp_tw_recycle` and do not recommend
enabling it._

You should also modify your open file settings to `100000`. This can be done on a linux-based OS
with the command: `ulimit -n 100000`.

## Testing with rosetta-cli
To validate `rosetta-rsk`, [install `rosetta-cli`](https://github.com/coinbase/rosetta-cli#install)
and run one of the following commands:
* `rosetta-cli check:data --configuration-file rosetta-cli-conf/testnet/config.json`
* `rosetta-cli check:construction --configuration-file rosetta-cli-conf/testnet/config.json`
* `rosetta-cli check:data --configuration-file rosetta-cli-conf/mainnet/config.json`

## Development
* `make deps` to install dependencies
* `make test` to run tests
* `make lint` to lint the source code
* `make salus` to check for security concerns
* `make build-local` to build a Docker image from the local context
* `make coverage-local` to generate a coverage report

## License
This project is available open source under the terms of the [Apache 2.0 License](https://opensource.org/licenses/Apache-2.0).

© 2020 Coinbase
