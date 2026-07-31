ARG XRAY_TUI_BASE_IMAGE=alpine:3.23
FROM ${XRAY_TUI_BASE_IMAGE}

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TZ=UTC

ARG XRAY_TUI_BASE_IMAGE
ARG XRAY_TUI_DOCKERFILE_SHA256
ARG XRAY_TUI_UID=1000

LABEL xray.tui.base-image="${XRAY_TUI_BASE_IMAGE}" \
      xray.tui.dockerfile-sha256="${XRAY_TUI_DOCKERFILE_SHA256}" \
      xray.tui.runtime-uid="${XRAY_TUI_UID}"

RUN apk add --no-cache \
    ansible-core \
    bash \
    curl \
    openssh-client \
    py3-pynacl \
    python3 \
    sshpass \
    tzdata

RUN cp /usr/share/zoneinfo/UTC /etc/localtime \
    && echo "UTC" > /etc/timezone

ENV ANSIBLE_COLLECTIONS_PATH=/usr/share/ansible/collections

RUN ansible-galaxy collection install community.docker \
    --collections-path /usr/share/ansible/collections

RUN addgroup -S user \
    && adduser -S -D -H -u "${XRAY_TUI_UID}" -G user -s /sbin/nologin user

WORKDIR /workspace
ENV HOME=/tmp
USER user
ENTRYPOINT ["/bin/bash", "/workspace/tui/entrypoint.sh"]
