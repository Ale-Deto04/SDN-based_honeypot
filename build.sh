#!/bin/bash

docker build -f Dockerfiles/Dockerfile.ryu -t kathara/ryu .
docker build -f Dockerfiles/Dockerfile.host -t kathara/host .
docker build -f Dockerfiles/Dockerfile.server -t kathara/server .
