# Linux Installation Guide

## Supported Distributions

- Ubuntu 20.04 LTS, 22.04 LTS, 24.04 LTS
- Debian 10 (Buster), 11 (Bullseye), 12 (Bookworm)
- RHEL 8, 9
- CentOS Stream 8, 9
- Fedora 38+
- openSUSE Leap 15.5+
- Arch Linux (current)

## Installation Methods

### Package Manager Installation

#### APT (Debian/Ubuntu)
```bash
# Add Supacrypt repository key
wget -qO - https://apt.supacrypt.io/gpg | sudo apt-key add -

# Add repository
echo "deb https://apt.supacrypt.io stable main" | \
    sudo tee /etc/apt/sources.list.d/supacrypt.list

# Update and install
sudo apt update
sudo apt install supacrypt-pkcs11

# Optional: development headers
sudo apt install supacrypt-pkcs11-dev
```

#### YUM/DNF (RHEL/Fedora)
```bash
# Add repository
sudo dnf config-manager --add-repo https://rpm.supacrypt.io/supacrypt.repo

# Install
sudo dnf install supacrypt-pkcs11

# For RHEL 8
sudo yum install supacrypt-pkcs11
```

#### Zypper (openSUSE)
```bash
# Add repository
sudo zypper addrepo https://rpm.supacrypt.io/opensuse/ supacrypt

# Install
sudo zypper install supacrypt-pkcs11
```

#### Pacman (Arch)
```bash
# From AUR
yay -S supacrypt-pkcs11

# Or manually
git clone https://aur.archlinux.org/supacrypt-pkcs11.git
cd supacrypt-pkcs11
makepkg -si
```

### Manual Installation

#### From Binary Package
```bash
# Download package
wget https://github.com/supacrypt/supacrypt-pkcs11/releases/download/v1.0.0/supacrypt-pkcs11-1.0.0-linux-x64.tar.gz

# Extract
sudo tar -xzf supacrypt-pkcs11-1.0.0-linux-x64.tar.gz -C /

# Update library cache
sudo ldconfig

# Verify installation
pkcs11-tool --module /usr/lib/supacrypt-pkcs11.so -I
```

#### From Source
```bash
# Install dependencies
sudo apt install build-essential cmake git libssl-dev

# Clone repository
git clone https://github.com/supacrypt/supacrypt-pkcs11.git
cd supacrypt-pkcs11

# Build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr
make -j$(nproc)

# Test
make test

# Install
sudo make install
sudo ldconfig
```

## Configuration

### System-Wide Configuration

Create `/etc/supacrypt/pkcs11.conf`:
```json
{
  "backend": {
    "endpoint": "backend.supacrypt.local:5000",
    "tls": {
      "enabled": true,
      "client_cert": "/etc/supacrypt/certs/client.crt",
      "client_key": "/etc/supacrypt/certs/client.key",
      "ca_cert": "/etc/supacrypt/certs/ca.crt"
    }
  },
  "logging": {
    "enabled": true,
    "level": "info",
    "file": "/var/log/supacrypt/pkcs11.log"
  }
}
```

### User Configuration

Create `~/.config/supacrypt/pkcs11.conf` for user-specific settings.

### Certificate Setup
```bash
# Create certificate directory
sudo mkdir -p /etc/supacrypt/certs
sudo chmod 755 /etc/supacrypt/certs

# Copy certificates
sudo cp client.crt client.key ca.crt /etc/supacrypt/certs/
sudo chmod 644 /etc/supacrypt/certs/*.crt
sudo chmod 600 /etc/supacrypt/certs/*.key

# Set ownership
sudo chown -R root:root /etc/supacrypt/certs
```

## Application Integration

### p11-kit Integration
```bash
# Create module configuration
sudo tee /usr/share/p11-kit/modules/supacrypt.module <<EOF
module: /usr/lib/supacrypt-pkcs11.so
trust-policy: yes
EOF

# List modules
p11-kit list-modules

# Test
p11tool --list-all
```

### NSS Integration
```bash
# Add to NSS database
modutil -add "Supacrypt PKCS#11" \
    -libfile /usr/lib/supacrypt-pkcs11.so \
    -dbdir sql:$HOME/.pki/nssdb

# Verify
modutil -list -dbdir sql:$HOME/.pki/nssdb

# Use with Chrome/Firefox
export NSS_DEFAULT_DB_TYPE=sql
```

### OpenSSL Integration
```bash
# Install engine
sudo apt install libengine-pkcs11-openssl

# Configure OpenSSL
cat >> ~/.openssl.cnf <<EOF
[openssl_init]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = /usr/lib/x86_64-linux-gnu/engines-1.1/libpkcs11.so
MODULE_PATH = /usr/lib/supacrypt-pkcs11.so
init = 0
EOF

# Test
openssl engine pkcs11 -t
```

### SSH Integration
```bash
# Find SSH key
ssh-keygen -D /usr/lib/supacrypt-pkcs11.so

# Add to SSH agent
ssh-add -s /usr/lib/supacrypt-pkcs11.so

# Use for authentication
ssh -I /usr/lib/supacrypt-pkcs11.so user@host
```

### Java Integration
```java
// Configure provider
String configName = "/etc/supacrypt/java.cfg";
Provider p = new sun.security.pkcs11.SunPKCS11(configName);
Security.addProvider(p);

// java.cfg content:
name = Supacrypt
library = /usr/lib/supacrypt-pkcs11.so
```

## Permissions and Security

### SELinux Configuration (RHEL/Fedora)
```bash
# Set context
sudo semanage fcontext -a -t lib_t "/usr/lib/supacrypt-pkcs11.so"
sudo restorecon -v /usr/lib/supacrypt-pkcs11.so

# Allow access
sudo setsebool -P httpd_can_network_connect 1  # For web servers
```

### AppArmor Configuration (Ubuntu)
```bash
# Add to /etc/apparmor.d/local/usr.bin.application
/usr/lib/supacrypt-pkcs11.so mr,
/etc/supacrypt/** r,
```

### File Permissions
```bash
# Library permissions
-rwxr-xr-x /usr/lib/supacrypt-pkcs11.so

# Configuration permissions
-rw-r--r-- /etc/supacrypt/pkcs11.conf
-rw-r--r-- /etc/supacrypt/certs/ca.crt
-rw-r--r-- /etc/supacrypt/certs/client.crt
-rw------- /etc/supacrypt/certs/client.key
```

## Logging

### System Logging
```bash
# View logs
sudo journalctl -u supacrypt-pkcs11

# Tail logs
sudo tail -f /var/log/supacrypt/pkcs11.log

# Log rotation
cat > /etc/logrotate.d/supacrypt <<EOF
/var/log/supacrypt/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
}
EOF
```

### Debug Logging
```bash
# Enable debug logging
export SUPACRYPT_LOG_LEVEL=debug
export SUPACRYPT_LOG_FILE=/tmp/supacrypt-debug.log

# Run application
your-application

# View debug output
cat /tmp/supacrypt-debug.log
```

## Performance Tuning

### System Limits
```bash
# Increase file descriptors
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# Apply immediately
ulimit -n 65536
```

### Network Optimization
```bash
# TCP keepalive
echo "net.ipv4.tcp_keepalive_time = 60" >> /etc/sysctl.conf
echo "net.ipv4.tcp_keepalive_intvl = 10" >> /etc/sysctl.conf
echo "net.ipv4.tcp_keepalive_probes = 6" >> /etc/sysctl.conf

# Apply
sudo sysctl -p
```

## Troubleshooting

### Common Issues

#### Library Not Found
```bash
# Check library path
ldconfig -p | grep supacrypt

# Add to library path
echo "/usr/lib" | sudo tee /etc/ld.so.conf.d/supacrypt.conf
sudo ldconfig
```

#### Permission Denied
```bash
# Check SELinux
getenforce
sudo setenforce 0  # Temporary disable for testing

# Check file permissions
ls -la /usr/lib/supacrypt-pkcs11.so
ls -la /etc/supacrypt/
```

#### Backend Connection Failed
```bash
# Test connectivity
nc -zv backend.supacrypt.local 5000

# Check DNS
nslookup backend.supacrypt.local

# Verify certificates
openssl s_client -connect backend.supacrypt.local:5000 \
    -cert /etc/supacrypt/certs/client.crt \
    -key /etc/supacrypt/certs/client.key \
    -CAfile /etc/supacrypt/certs/ca.crt
```

### Debug Tools
```bash
# PKCS#11 tool
pkcs11-tool --module /usr/lib/supacrypt-pkcs11.so -L

# strace
strace -e openat your-application 2>&1 | grep supacrypt

# ldd
ldd /usr/lib/supacrypt-pkcs11.so
```

## Uninstallation

### Package Manager
```bash
# Debian/Ubuntu
sudo apt remove supacrypt-pkcs11
sudo apt purge supacrypt-pkcs11  # Also removes config

# RHEL/Fedora
sudo dnf remove supacrypt-pkcs11
```

### Manual Cleanup
```bash
# Remove library
sudo rm /usr/lib/supacrypt-pkcs11.so

# Remove configuration
sudo rm -rf /etc/supacrypt

# Remove logs
sudo rm -rf /var/log/supacrypt

# Update library cache
sudo ldconfig
```