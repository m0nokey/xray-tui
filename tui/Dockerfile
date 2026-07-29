ARG XRAY_TUI_BASE_IMAGE=alpine:3.23
FROM ${XRAY_TUI_BASE_IMAGE}

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

ARG XRAY_TUI_BASE_IMAGE
ARG XRAY_TUI_DOCKERFILE_SHA256

LABEL xray.tui.base-image="${XRAY_TUI_BASE_IMAGE}" \
      xray.tui.dockerfile-sha256="${XRAY_TUI_DOCKERFILE_SHA256}"

RUN apk add --no-cache \
    ansible-core \
    bash \
    curl \
    openssh-client \
    py3-pynacl \
    python3 \
    sshpass

ENV ANSIBLE_COLLECTIONS_PATH=/usr/share/ansible/collections

RUN ansible-galaxy collection install community.docker \
    --collections-path /usr/share/ansible/collections

RUN addgroup -S user \
    && adduser -S -D -H -G user -s /sbin/nologin user

WORKDIR /workspace
ENV HOME=/tmp
USER user
ENTRYPOINT ["/bin/bash", "/workspace/xray-tui.sh"]
