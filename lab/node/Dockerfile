FROM ubuntu:24.04@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289

ARG DEBIAN_FRONTEND=noninteractive
ARG XUI_VERSION=3.11.0
ARG XUI_SHA256=0ddfa4702f595442e2962acd81addc768fdacaa4ff2672c971a0463dae744916

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        iproute2 \
        iptables \
        jq \
        openssh-server \
        openssl \
        procps \
        tzdata \
    && rm -f /etc/ssh/ssh_host_* \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSLo /tmp/x-ui.tar.gz "https://github.com/MHSanaei/3x-ui/releases/download/v${XUI_VERSION}/x-ui-linux-amd64.tar.gz" \
    && echo "${XUI_SHA256}  /tmp/x-ui.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/x-ui.tar.gz -C /usr/local \
    && rm -f /tmp/x-ui.tar.gz \
    && /usr/local/x-ui/x-ui -v

ENV XUI_IN_DOCKER=true \
    XUI_MAIN_FOLDER=/usr/local/x-ui \
    XUI_ENABLE_FAIL2BAN=false \
    XUI_PORT=2053 \
    XUI_MEMORY_LIMIT=256

COPY --chmod=0755 entrypoint.sh /usr/local/bin/lab-entrypoint

EXPOSE 22 2053

HEALTHCHECK --interval=5s --timeout=3s --retries=12 \
    CMD test -s /run/x-ui.pid \
        && kill -0 "$(cat /run/x-ui.pid)" \
        && ssh-keyscan -T 2 127.0.0.1 >/dev/null 2>&1 \
        || exit 1

ENTRYPOINT ["/usr/local/bin/lab-entrypoint"]
