# Supacrypt PKCS#11 Troubleshooting Guide

## Common Issues and Solutions

### Connection Issues

#### Error: CKR_DEVICE_ERROR during C_Initialize

**Symptoms:**
- C_Initialize returns CKR_DEVICE_ERROR
- "Backend connection failed" in logs

**Causes:**
1. Backend service not running
2. Network connectivity issues
3. Incorrect endpoint configuration
4. Firewall blocking connection

**Solutions:**
```bash
# 1. Check backend status
curl -k https://backend.supacrypt.local:5000/health

# 2. Test network connectivity
ping backend.supacrypt.local
nc -zv backend.supacrypt.local 5000

# 3. Verify configuration
cat /etc/supacrypt/pkcs11.conf | jq .backend.endpoint

# 4. Check firewall
sudo iptables -L -n | grep 5000
```

#### Error: Certificate Verification Failed

**Symptoms:**
- "TLS handshake failed" in logs
- CKR_DEVICE_ERROR with SSL errors

**Solutions:**
```bash
# Verify certificate validity
openssl x509 -in /etc/supacrypt/client.crt -text -noout

# Check certificate chain
openssl verify -CAfile /etc/supacrypt/ca.crt /etc/supacrypt/client.crt

# Test mTLS connection
openssl s_client -connect backend:5000 \
    -cert /etc/supacrypt/client.crt \
    -key /etc/supacrypt/client.key \
    -CAfile /etc/supacrypt/ca.crt
```

### Library Loading Issues

#### Error: Library Not Found

**Symptoms:**
- "cannot open shared object file"
- Application fails to load PKCS#11 module

**Solutions:**
```bash
# Update library cache
sudo ldconfig

# Check library dependencies
ldd /usr/lib/supacrypt-pkcs11.so

# Add to LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/usr/lib:$LD_LIBRARY_PATH

# Verify library architecture
file /usr/lib/supacrypt-pkcs11.so
```

#### Error: Symbol Not Found

**Symptoms:**
- "undefined symbol" errors
- C_GetFunctionList not found

**Solutions:**
```bash
# Check exported symbols
nm -D /usr/lib/supacrypt-pkcs11.so | grep C_GetFunctionList

# Verify library version
strings /usr/lib/supacrypt-pkcs11.so | grep VERSION

# Rebuild with proper flags
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON
```

### Operational Issues

#### Error: CKR_OPERATION_ACTIVE

**Symptoms:**
- Cannot start new operation
- Previous operation not completed

**Solutions:**
```c
// Cancel any active operation
C_SignInit(hSession, NULL, 0);  // Cancel signing
C_VerifyInit(hSession, NULL, 0); // Cancel verify

// Or close and reopen session
C_CloseSession(hSession);
C_OpenSession(slot, flags, NULL, NULL, &hSession);
```

#### Error: CKR_KEY_HANDLE_INVALID

**Symptoms:**
- Key not found errors
- Object handle invalid

**Causes:**
1. Key deleted on backend
2. Session closed
3. Handle corruption

**Solutions:**
```c
// Re-find the key
CK_ATTRIBUTE template[] = {
    {CKA_LABEL, label, labelLen}
};
C_FindObjectsInit(hSession, template, 1);
C_FindObjects(hSession, &hKey, 1, &count);
C_FindObjectsFinal(hSession);
```

### Performance Issues

#### Slow Operations

**Symptoms:**
- Operations taking >100ms
- Timeouts during signing

**Solutions:**
```bash
# 1. Check network latency
ping -c 10 backend.supacrypt.local

# 2. Increase connection pool
export SUPACRYPT_POOL_SIZE=8

# 3. Enable connection keepalive
echo "net.ipv4.tcp_keepalive_time = 60" | sudo tee -a /etc/sysctl.conf

# 4. Check backend load
curl https://backend:5000/metrics
```

#### Memory Leaks

**Symptoms:**
- Increasing memory usage
- Application crash after extended use

**Solutions:**
```bash
# Use valgrind to detect leaks
valgrind --leak-check=full --show-leak-kinds=all \
    ./your-application

# Common fixes:
# - Always call C_Finalize
# - Close all sessions
# - Free allocated buffers
```

### Platform-Specific Issues

#### Linux: SELinux Denials

```bash
# Check SELinux denials
sudo ausearch -m avc -ts recent

# Create policy module
sudo audit2allow -M supacrypt-pkcs11
sudo semodule -i supacrypt-pkcs11.pp
```

#### Windows: DLL Loading Failed

```powershell
# Check dependencies
dumpbin /dependents supacrypt-pkcs11.dll

# Install Visual C++ Runtime
# Download from Microsoft

# Register DLL
regsvr32 supacrypt-pkcs11.dll
```

#### macOS: Code Signing Issues

```bash
# Check code signature
codesign -vvv /usr/local/lib/supacrypt-pkcs11.dylib

# Allow unsigned library (development only)
sudo spctl --add /usr/local/lib/supacrypt-pkcs11.dylib
```

## Debug Techniques

### Enable Debug Logging

```c
// In code
SC_SetLogging(CK_TRUE, 3, "/tmp/pkcs11-debug.log");

// Via environment
export SUPACRYPT_LOG_LEVEL=debug
export SUPACRYPT_LOG_FILE=/tmp/pkcs11-debug.log
```

### Use PKCS#11 Spy

```bash
# Install pkcs11-spy
export PKCS11SPY=/usr/lib/supacrypt-pkcs11.so
export PKCS11SPY_OUTPUT=/tmp/pkcs11-spy.log

# Use spy library
pkcs11-tool --module /usr/lib/pkcs11-spy.so -L
```

### Network Tracing

```bash
# Capture gRPC traffic
sudo tcpdump -i any -w pkcs11.pcap host backend.supacrypt.local

# Analyze with Wireshark
wireshark pkcs11.pcap
# Filter: grpc
```

### Core Dumps

```bash
# Enable core dumps
ulimit -c unlimited
echo "/tmp/core.%e.%p" | sudo tee /proc/sys/kernel/core_pattern

# Analyze core
gdb /usr/lib/supacrypt-pkcs11.so /tmp/core.pkcs11.12345
(gdb) bt full
(gdb) info threads
```

## Performance Optimization

### Connection Pooling
```c
// Increase pool size for concurrent operations
config.connection_pool_size = 16;
```

### Session Caching
```c
// Reuse sessions across operations
static CK_SESSION_HANDLE cached_session = CK_INVALID_HANDLE;

CK_SESSION_HANDLE get_session() {
    if (cached_session == CK_INVALID_HANDLE) {
        C_OpenSession(1, CKF_SERIAL_SESSION, NULL, NULL, &cached_session);
    }
    return cached_session;
}
```

### Batch Operations
```c
// Use multi-part operations for large data
C_SignInit(hSession, &mech, hKey);
for (size_t i = 0; i < data_len; i += CHUNK_SIZE) {
    C_SignUpdate(hSession, data + i, MIN(CHUNK_SIZE, data_len - i));
}
C_SignFinal(hSession, signature, &sig_len);
```

## Getting Help

### Log Collection Script
```bash
#!/bin/bash
# collect-logs.sh

echo "Collecting Supacrypt PKCS#11 diagnostics..."

# Create report directory
REPORT_DIR="/tmp/supacrypt-report-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$REPORT_DIR"

# System info
uname -a > "$REPORT_DIR/system.txt"
lsb_release -a >> "$REPORT_DIR/system.txt" 2>/dev/null

# Library info
ldd /usr/lib/supacrypt-pkcs11.so > "$REPORT_DIR/library-deps.txt"
nm -D /usr/lib/supacrypt-pkcs11.so > "$REPORT_DIR/library-symbols.txt"

# Configuration
cp /etc/supacrypt/pkcs11.conf "$REPORT_DIR/" 2>/dev/null

# Recent logs
journalctl -u supacrypt-pkcs11 --since "1 hour ago" > "$REPORT_DIR/journal.log"
cp /var/log/supacrypt/pkcs11.log "$REPORT_DIR/" 2>/dev/null

# Network test
nc -zv backend.supacrypt.local 5000 &> "$REPORT_DIR/network-test.txt"

# Create archive
tar -czf "$REPORT_DIR.tar.gz" -C /tmp "$(basename $REPORT_DIR)"
echo "Report saved to: $REPORT_DIR.tar.gz"
```

### Support Channels

- GitHub Issues: https://github.com/supacrypt/supacrypt-pkcs11/issues
- Documentation: https://docs.supacrypt.io/pkcs11
- Community Forum: https://forum.supacrypt.io
- Email Support: support@supacrypt.io (Enterprise customers)

When reporting issues, please include:
1. OS and version
2. Supacrypt PKCS#11 version
3. Error messages and logs
4. Steps to reproduce
5. Diagnostic report from collect-logs.sh