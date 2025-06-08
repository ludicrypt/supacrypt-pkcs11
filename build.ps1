# build.ps1

param(
    [string]$BuildType = "Release"
)

$BuildDir = "build-$($BuildType.ToLower())"

Write-Host "Building supacrypt-pkcs11 in $BuildType mode..." -ForegroundColor Green

# Create build directory
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
Set-Location $BuildDir

# Configure
cmake .. `
    -G "Visual Studio 17 2022" `
    -A x64 `
    -DCMAKE_BUILD_TYPE=$BuildType `
    -DBUILD_TESTING=ON `
    -DBUILD_EXAMPLES=ON

# Build
cmake --build . --config $BuildType --parallel

# Run tests
ctest -C $BuildType --output-on-failure

Write-Host "Build complete!" -ForegroundColor Green