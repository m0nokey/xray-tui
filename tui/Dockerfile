FROM alpine:3.23

RUN apk add --no-cache \
    ansible \
    bash \
    curl \
    openssh-client \
    py3-pynacl \
    python3 \
    sshpass

RUN ansible-galaxy collection install community.docker ansible.posix

WORKDIR /workspace
ENTRYPOINT ["/workspace/xray-tui.sh"]
