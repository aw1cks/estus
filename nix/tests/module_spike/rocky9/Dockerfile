FROM rockylinux:9
RUN dnf install -y -q systemd openssh-server sudo python3 python3-libdnf procps-ng rpm-build createrepo_c && \
    dnf clean all
RUN mkdir -p /etc/sysctl.d /opt/spike-repo /opt/spike-fixture /root/rpmbuild/SPECS && \
    echo 'hello spike' > /opt/spike-fixture/sample.txt && \
    ln -s /opt/spike-fixture/sample.txt /opt/spike-fixture/sample.link && \
    printf 'Name: estus-spike-pkg\nVersion: 1.0\nRelease: 1\nSummary: Disposable spike package\nLicense: MIT\nBuildArch: noarch\n\n%%description\nDisposable spike package.\n\n%%install\nmkdir -p %%{buildroot}/usr/share/estus-spike\necho spike-1.0 > %%{buildroot}/usr/share/estus-spike/marker\n\n%%files\n/usr/share/estus-spike/marker\n' > /root/rpmbuild/SPECS/estus-spike-pkg.spec && \
    rpmbuild -bb /root/rpmbuild/SPECS/estus-spike-pkg.spec >/dev/null && \
    cp /root/rpmbuild/RPMS/noarch/estus-spike-pkg-1.0-1.noarch.rpm /opt/spike-repo/ && \
    rm -rf /root/rpmbuild && \
    createrepo_c -q /opt/spike-repo && \
    rm -f /etc/yum.repos.d/*.repo && \
    printf '[estus-spike]\nname=Estus Spike Repo\nbaseurl=file:///opt/spike-repo\nenabled=1\ngpgcheck=0\n' > /etc/yum.repos.d/estus-spike.repo && \
    dnf makecache -q
RUN printf '[Unit]\nDescription=Estus Spike Fixture Service\nAfter=network.target\n[Service]\nType=simple\nExecStart=/bin/sh -c "while true; do sleep 60; done"\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/estus-spike.service && \
    systemctl enable estus-spike.service
RUN useradd -m -u 1000 -s /bin/bash mcp && \
    useradd -m -u 1001 -s /bin/bash mcp-admin && \
    echo 'mcp-admin ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/mcp-admin && \
    chmod 0440 /etc/sudoers.d/mcp-admin && \
    ssh-keygen -A && \
    systemctl enable sshd
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
