# ═══════════════════════════════════════════════════════════════════════════
# RPM Spec file for Linux Incident Compiler
# Supports: Rocky Linux 9, RHEL 9, Fedora 39+
# ═══════════════════════════════════════════════════════════════════════════

Name:           linux-incident-compiler
Version:        0.1.0
Release:        1%{?dist}
Summary:        Linux Incident Compiler - Security incident detection and response

License:        MIT
URL:            https://github.com/yourorg/linux-incident-compiler
Source0:        %{name}-%{version}.tar.gz

# Build requirements
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  openssl-devel
BuildRequires:  pkgconf-pkg-config
BuildRequires:  systemd-rpm-macros

# Optional eBPF build requirements
BuildRequires:  clang
BuildRequires:  elfutils-libelf-devel
BuildRequires:  libbpf-devel

# Runtime requirements
Requires:       openssl >= 3.0
Requires:       systemd
Requires(pre):  shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

# Optional runtime requirements
Recommends:     elfutils-libelf
Recommends:     libbpf

%description
Linux Incident Compiler provides endpoint detection and response (EDR)
capabilities for Linux systems.

Features:
- Process execution monitoring
- File system telemetry
- Network connection tracking
- eBPF-based kernel tracing (optional)
- Playbook-based incident detection

Supported: Rocky Linux 9, RHEL 9, Fedora 39+

# ─────────────────────────────────────────────────────────────────────────────
# Prep
# ─────────────────────────────────────────────────────────────────────────────
%prep
%autosetup

# ─────────────────────────────────────────────────────────────────────────────
# Build
# ─────────────────────────────────────────────────────────────────────────────
%build
# Install Rust if not available (CI should have it)
if ! command -v cargo &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Build release binaries
cargo build --release -p edr-server
cargo build --release -p edr-locald

# Build capture agent with eBPF support
cargo build --release -p agent-linux --features with-ebpf-load || \
    cargo build --release -p agent-linux

# ─────────────────────────────────────────────────────────────────────────────
# Install
# ─────────────────────────────────────────────────────────────────────────────
%install
rm -rf %{buildroot}

# Create directory structure
mkdir -p %{buildroot}/opt/edr/bin
mkdir -p %{buildroot}/opt/edr/playbooks/linux
mkdir -p %{buildroot}%{_unitdir}
mkdir -p %{buildroot}%{_docdir}/%{name}
mkdir -p %{buildroot}/var/lib/edr

# Install binaries
install -m 755 target/release/edr-server %{buildroot}/opt/edr/bin/
install -m 755 target/release/edr-locald %{buildroot}/opt/edr/bin/
[ -f target/release/capture_linux_rotating ] && \
    install -m 755 target/release/capture_linux_rotating %{buildroot}/opt/edr/bin/

# Install systemd units
install -m 644 systemd/edr-server.service %{buildroot}%{_unitdir}/
install -m 644 systemd/edr-locald.service %{buildroot}%{_unitdir}/
install -m 644 systemd/edr-capture.service %{buildroot}%{_unitdir}/
install -m 644 systemd/edr-capture-caps.service %{buildroot}%{_unitdir}/
install -m 644 systemd/edr.target %{buildroot}%{_unitdir}/

# Install playbooks
cp -r playbooks/linux/* %{buildroot}/opt/edr/playbooks/linux/ 2>/dev/null || true

# Install documentation
install -m 644 README.md %{buildroot}%{_docdir}/%{name}/
[ -f docs/INSTALL_LINUX.md ] && \
    install -m 644 docs/INSTALL_LINUX.md %{buildroot}%{_docdir}/%{name}/

# ─────────────────────────────────────────────────────────────────────────────
# Pre-install
# ─────────────────────────────────────────────────────────────────────────────
%pre
# Create system user
getent group edr >/dev/null || groupadd -r edr
getent passwd edr >/dev/null || \
    useradd -r -g edr -d /var/lib/edr -s /sbin/nologin \
    -c "EDR Service Account" edr
exit 0

# ─────────────────────────────────────────────────────────────────────────────
# Post-install
# ─────────────────────────────────────────────────────────────────────────────
%post
# Create runtime directories
mkdir -p /var/lib/edr/telemetry/segments
mkdir -p /var/lib/edr/telemetry/runs
mkdir -p /var/lib/edr/telemetry/db
mkdir -p /var/lib/edr/logs
mkdir -p /var/lib/edr/license
chown -R edr:edr /var/lib/edr

# Reload systemd
%systemd_post edr-server.service edr-locald.service edr-capture.service edr.target

echo "═══════════════════════════════════════════════════════════════"
echo "Linux Incident Compiler installed successfully!"
echo ""
echo "To start the services:"
echo "  sudo systemctl start edr.target"
echo ""
echo "To enable at boot:"
echo "  sudo systemctl enable edr.target"
echo "═══════════════════════════════════════════════════════════════"

# ─────────────────────────────────────────────────────────────────────────────
# Pre-uninstall
# ─────────────────────────────────────────────────────────────────────────────
%preun
%systemd_preun edr.target edr-server.service edr-locald.service edr-capture.service edr-capture-caps.service

# ─────────────────────────────────────────────────────────────────────────────
# Post-uninstall
# ─────────────────────────────────────────────────────────────────────────────
%postun
%systemd_postun_with_restart edr.target edr-server.service edr-locald.service edr-capture.service

# ─────────────────────────────────────────────────────────────────────────────
# Files
# ─────────────────────────────────────────────────────────────────────────────
%files
%license LICENSE
%doc README.md
%doc %{_docdir}/%{name}/

# Binaries
%dir /opt/edr
%dir /opt/edr/bin
/opt/edr/bin/edr-server
/opt/edr/bin/edr-locald
/opt/edr/bin/capture_linux_rotating

# Playbooks
%dir /opt/edr/playbooks
%dir /opt/edr/playbooks/linux
%config(noreplace) /opt/edr/playbooks/linux/

# Systemd units
%{_unitdir}/edr-server.service
%{_unitdir}/edr-locald.service
%{_unitdir}/edr-capture.service
%{_unitdir}/edr-capture-caps.service
%{_unitdir}/edr.target

# Runtime directories (created by %post)
%ghost %dir /var/lib/edr
%ghost %dir /var/lib/edr/telemetry
%ghost %dir /var/lib/edr/logs
%ghost %dir /var/lib/edr/license

# ─────────────────────────────────────────────────────────────────────────────
# Changelog
# ─────────────────────────────────────────────────────────────────────────────
%changelog
* %(date +"%a %b %d %Y") EDR Team <support@example.com> - 0.1.0-1
- Initial package release
- Multi-distro support: Rocky Linux 9, RHEL 9
- Systemd service integration
- eBPF capture support (optional)
