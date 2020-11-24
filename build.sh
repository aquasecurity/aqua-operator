#!/bin/bash

docker run \
        --rm -it \
        -w "/go/src/github.org/aquasecurity/aqua-operator" \
        -v `pwd`:/go/src/github.org/aquasecurity/aqua-operator \
        -v //var/run/docker.sock:/var/run/docker.sock \
        --privileged \
        aquasec/operator-sdk:latest \
        operator-sdk build $@