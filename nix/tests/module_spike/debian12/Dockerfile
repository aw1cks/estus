FROM debian:12-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
      systemd systemd-sysv openssh-server sudo python3 python3-apt procps dpkg-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /run/sshd /opt/spike-repo /opt/spike-fixture && \
    echo 'hello spike' > /opt/spike-fixture/sample.txt && \
    ln -s /opt/spike-fixture/sample.txt /opt/spike-fixture/sample.link && \
    mkdir -p /tmp/pkg/DEBIAN /tmp/pkg/usr/share/estus-spike && \
    printf 'Package: estus-spike-pkg\nVersion: 1.0\nSection: misc\nPriority: optional\nArchitecture: all\nMaintainer: Estus <estus@example.invalid>\nDescription: Disposable spike package\n' > /tmp/pkg/DEBIAN/control && \
    echo 'spike-1.0' > /tmp/pkg/usr/share/estus-spike/marker && \
    dpkg-deb --build /tmp/pkg /opt/spike-repo/estus-spike-pkg_1.0_all.deb && \
    rm -rf /tmp/pkg && \
    (cd /opt/spike-repo && dpkg-scanpackages . /dev/null > Packages && gzip -k Packages) && \
    echo 'deb [trusted=yes] file:/opt/spike-repo ./' > /etc/apt/sources.list.d/estus-spike.list && \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources && \
    apt-get update -qq
RUN printf '[Unit]\nDescription=Estus Spike Fixture Service\nAfter=network.target\n[Service]\nType=simple\nExecStart=/bin/sh -c "while true; do sleep 60; done"\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/estus-spike.service && \
    systemctl enable estus-spike.service
RUN useradd -m -u 1000 -s /bin/bash mcp && \
    useradd -m -u 1001 -s /bin/bash mcp-admin && \
    echo 'mcp-admin ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/mcp-admin && \
    chmod 0440 /etc/sudoers.d/mcp-admin && \
    systemctl enable ssh
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
