FROM registry.access.redhat.com/ubi8/ubi-minimal:latest

ENV OPERATOR=/usr/local/bin/aqua-operator \
    USER_UID=1001 \
    USER_NAME=aqua-operator

LABEL name="Aqua Operator" \
      vendor="Aqua Security Software Ltd." \
      version="v1.0.1" \
      release="1" \
      summary="Aqua Security Operator." \
      description="The Aqua Security Operator runs within a Openshift (or Kubernetes) cluster, and provides a means to deploy and manage the Aqua Security cluster and components"

COPY licenses /licenses

COPY build/_output/bin/aqua-operator ${OPERATOR}

COPY build/bin /usr/local/bin
RUN  /usr/local/bin/user_setup

ENTRYPOINT ["/usr/local/bin/entrypoint"]

USER ${USER_UID}
