# Copyright 2020 Coinbase, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Support golang and necessary base dependencies
FROM golang:1.15.5-alpine3.12 as golang-builder

RUN mkdir -p /app \
  && chown -R nobody:nogroup /app
WORKDIR /app

RUN apk --no-cache add curl make gcc g++ git linux-headers

# Compile geth
FROM golang-builder as geth-builder

# VERSION: go-ethereum v.1.9.24
RUN git clone https://github.com/ethereum/go-ethereum \
  && cd go-ethereum \
  && git checkout cc05b050df5f88e80bb26aaf6d2f339c49c2d702

RUN cd go-ethereum \
  && make geth

RUN mv go-ethereum/build/bin/geth /app/geth \
  && rm -rf go-ethereum

# Compile rosetta-rsk
FROM golang-builder as rosetta-builder

# Use native remote build context to build in any directory
COPY . src 
RUN cd src \
  && go build

RUN mv src/rosetta-rsk /app/rosetta-rsk \
  && mkdir /app/ethereum \
  && mv src/ethereum/call_tracer.js /app/ethereum/call_tracer.js \
  && mv src/ethereum/geth.toml /app/ethereum/geth.toml \
  && rm -rf src 

## Build Final Image
FROM alpine:3.12

RUN mkdir -p /app \
  && chown -R nobody:nogroup /app \
  && mkdir -p /data \
  && chown -R nobody:nogroup /data

WORKDIR /app

# Copy binary from geth-builder
COPY --from=geth-builder /app/geth /app/geth

# Copy binary from rosetta-builder
COPY --from=rosetta-builder /app/ethereum /app/ethereum
COPY --from=rosetta-builder /app/rosetta-rsk /app/rosetta-rsk

# Set permissions for everything added to /app
RUN chmod -R 755 /app/*

CMD ["/app/rosetta-rsk", "run"]
