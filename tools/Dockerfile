FROM golang:1.13.6-alpine3.10

RUN apk update \
    && apk upgrade \
    && apk add --no-cache bash curl git openssh make mercurial openrc docker

# curl for docker image
# git, mercurial, docker for Operator SDK
# bash, openssh, make, openrc for QoL

ARG RELEASE_VERSION=v0.15.1
ARG KUBECTL_VERSION=v1.15.0

# Install Operator SDK
RUN curl -OJL https://github.com/operator-framework/operator-sdk/releases/download/${RELEASE_VERSION}/operator-sdk-${RELEASE_VERSION}-x86_64-linux-gnu \
    && chmod +x operator-sdk-${RELEASE_VERSION}-x86_64-linux-gnu \
    && cp operator-sdk-${RELEASE_VERSION}-x86_64-linux-gnu /usr/local/bin/operator-sdk \
    && rm operator-sdk-${RELEASE_VERSION}-x86_64-linux-gnu

# Operator SDK says it needs Kubectl, not yet sure why though
RUN curl -LO https://storage.googleapis.com/kubernetes-release/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl \
    && chmod +x ./kubectl \
    && mv ./kubectl /usr/local/bin/kubectl

# From Operator SDK docs
ENV GO111MODULE=on

# Need /sys/fs/cgroup to not be read-only, when using Docker
VOLUME [ "/sys/fs/cgroup", "/go/src" ]
