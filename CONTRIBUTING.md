# Contributing to Supacrypt PKCS#11

We welcome contributions to the Supacrypt PKCS#11 provider! This guide explains how to set up your development environment and submit changes.

## Development Setup

### Prerequisites

- C++ compiler with C++20 support (GCC 10+, Clang 12+, MSVC 2019+)
- CMake 3.20+
- Git
- OpenSSL development headers
- Google Test (automatically fetched)
- Docker (for integration tests)

### Building from Source

```bash
# Clone repository
git clone https://github.com/supacrypt/supacrypt-pkcs11.git
cd supacrypt-pkcs11

# Create build directory
mkdir build && cd build

# Configure (with all optional features)
cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_TESTING=ON \
    -DBUILD_EXAMPLES=ON \
    -DBUILD_BENCHMARKS=ON \
    -DENABLE_COVERAGE=ON \
    -DENABLE_SANITIZERS=ON

# Build
make -j$(nproc)

# Run tests
make test

# Generate coverage report
make coverage
```

## Code Style

We follow the C++ Core Guidelines and use clang-format for consistency.

### Formatting

```bash
# Format all source files
find src include tests -name "*.cpp" -o -name "*.h" | \
    xargs clang-format -i

# Check formatting
find src include tests -name "*.cpp" -o -name "*.h" | \
    xargs clang-format --dry-run --Werror
```

### Naming Conventions

- Classes: `PascalCase`
- Functions: `camelCase`
- Variables: `camelCase`
- Constants: `UPPER_SNAKE_CASE`
- Files: `snake_case.cpp`

## Testing

### Unit Tests

```bash
# Run all unit tests
./tests/unit/supacrypt-pkcs11-unit-tests

# Run specific test
./tests/unit/supacrypt-pkcs11-unit-tests --gtest_filter="StateManagerTest.*"

# Run with valgrind
valgrind --leak-check=full ./tests/unit/supacrypt-pkcs11-unit-tests
```

### Integration Tests

```bash
# Start test backend
docker run -d --name test-backend \
    -p 5001:5000 \
    supacrypt/backend:test

# Run integration tests
./tests/integration/supacrypt-pkcs11-integration-tests

# Cleanup
docker stop test-backend && docker rm test-backend
```

### Performance Tests

```bash
# Run benchmarks
./tests/benchmarks/supacrypt-pkcs11-benchmarks

# Generate detailed report
./tests/benchmarks/supacrypt-pkcs11-benchmarks \
    --benchmark_format=json \
    --benchmark_out=results.json
```

## Submitting Changes

### Workflow

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Update documentation
6. Submit pull request

### Commit Messages

Follow the Conventional Commits specification:

```
type(scope): subject

body

footer
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `test`: Testing
- `perf`: Performance
- `refactor`: Code refactoring
- `ci`: CI/CD changes

Example:
```
feat(crypto): add support for RSA-PSS signing

- Implement RSA-PSS mechanism support
- Add padding parameter validation
- Update mechanism list

Closes #123
```

### Pull Request Process

1. Ensure all tests pass
2. Update relevant documentation
3. Add entry to CHANGELOG.md
4. Request review from maintainers

## Development Tips

### Debug Build

```bash
# Enable all debug features
cmake .. -DCMAKE_BUILD_TYPE=Debug \
         -DENABLE_SANITIZERS=ON \
         -DCMAKE_CXX_FLAGS="-O0 -g3"
```

### Using GDB

```bash
# Debug with GDB
gdb ./your-test-program
(gdb) set environment LD_LIBRARY_PATH=./src
(gdb) break C_Initialize
(gdb) run
```

### Memory Debugging

```bash
# AddressSanitizer
export ASAN_OPTIONS=detect_leaks=1
./tests/unit/supacrypt-pkcs11-unit-tests

# Valgrind
valgrind --tool=memcheck --leak-check=full \
         --show-leak-kinds=all ./your-program
```

## Architecture Overview

### Component Diagram

```
┌─────────────────┐
│   Application   │
└────────┬────────┘
         │ PKCS#11 API
┌────────▼────────┐
│  State Manager  │ ← Singleton, manages global state
├─────────────────┤
│ Session Manager │ ← Per-session state and operations
├─────────────────┤
│  Object Cache   │ ← Key handle management
├─────────────────┤
│ gRPC Pool       │ ← Connection management
├─────────────────┤
│ Circuit Breaker │ ← Resilience
└────────┬────────┘
         │ gRPC + mTLS
┌────────▼────────┐
│ Backend Service │
└─────────────────┘
```

### Adding New Features

1. Update protobuf if needed
2. Implement in appropriate layer
3. Add error handling
4. Update tests
5. Document changes

## Release Process

1. Update version in CMakeLists.txt
2. Update CHANGELOG.md
3. Tag release: `git tag -s v1.2.3`
4. Push tag: `git push origin v1.2.3`
5. CI builds and publishes

## Getting Help

- Discord: https://discord.gg/supacrypt
- Discussions: https://github.com/supacrypt/supacrypt-pkcs11/discussions
- Email: dev@supacrypt.io

## License

By contributing, you agree that your contributions will be licensed under the MIT License.