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
FROM golang:1.16 as golang-builder

RUN mkdir -p /app \
  && chown -R nobody:nogroup /app
WORKDIR /app

RUN apt-get update && \
    apt-get install -y make gcc g++ curl build-essential jq findutils && \
    rm -rf /var/lib/apt/lists/*

# Download latest rskj release
FROM golang-builder as rskj-downloader

WORKDIR /app

RUN curl --silent "https://api.github.com/repos/rsksmart/rskj/releases/latest" | \
    jq -r '.assets[] | select(.name | test("^rskj-core.*\\.jar$")).browser_download_url' | \
    xargs curl -L -o rskj-core-latest.jar && \
    mkdir rsk && \
    mv rskj-core-latest.jar /app/rsk

# Compile rosetta-rsk
FROM golang-builder as rosetta-builder

# Use native remote build context to build in any directory
COPY . src
RUN cd src \
  && go build

RUN mv src/rosetta-rsk /app/rosetta-rsk \
  && mkdir /app/rsk \
  && mv src/rsk/rsk.conf /app/rsk/rsk.conf \
  && rm -rf src

## Build Final Image
FROM openjdk:8

RUN mkdir -p /app \
  && chown -R nobody:nogroup /app \
  && mkdir -p /data \
  && chown -R nobody:nogroup /data

WORKDIR /app

# Copy jar from rsk-builder
COPY --from=rskj-downloader /app/rsk/rskj-core-latest.jar .
# Copy binary from rosetta-builder
COPY --from=rosetta-builder /app/rsk /app/rsk
COPY --from=rosetta-builder /app/rosetta-rsk /app/rosetta-rsk

# Set permissions for everything added to /app
RUN chmod -R 755 /app/*

CMD ["./rosetta-rsk", "run"]
