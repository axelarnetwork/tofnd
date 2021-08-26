#!/usr/bin/env bash

container_id=$(docker create axelar/tofnd:latest)
docker cp "$container_id":/usr/local/bin/tofnd ./bin/
docker rm -v "$container_id"
