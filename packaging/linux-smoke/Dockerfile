FROM debian:bookworm-slim
RUN apt-get -o Acquire::Retries=3 update && apt-get -o Acquire::Retries=3 install -y --no-install-recommends \
    dbus fish iproute2 nftables openssh-server sudo systemd ufw \
    && rm -rf /var/lib/apt/lists/*
COPY fixture.sh host-smoke legacy-install.sh migration-install.sh previous-update /fixture/
ENV container=docker
CMD ["/usr/lib/systemd/systemd"]
