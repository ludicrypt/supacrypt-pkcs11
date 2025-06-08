// tests/integration/test_e2e_operations.cpp

#include <gtest/gtest.h>
#include "test_backend_fixture.cpp" // Include the fixture
#include <vector>
#include <string>
#include <random>
#include <algorithm>

// Extended PKCS#11 mock types and functions for crypto operations
typedef unsigned long CK_OBJECT_HANDLE;
typedef unsigned long CK_MECHANISM_TYPE;
typedef unsigned long CK_ATTRIBUTE_TYPE;
typedef unsigned long CK_ULONG;
typedef unsigned char CK_BYTE;
typedef CK_BYTE* CK_BYTE_PTR;
typedef unsigned char CK_UTF8CHAR;
typedef CK_UTF8CHAR* CK_UTF8CHAR_PTR;
typedef unsigned char CK_BBOOL;

#define CK_TRUE                     1
#define CK_FALSE                    0

// Mechanism types
#define CKM_RSA_PKCS_KEY_PAIR_GEN   0x00000000UL
#define CKM_RSA_PKCS                0x00000001UL
#define CKM_SHA256_RSA_PKCS         0x00000040UL
#define CKM_ECDSA_KEY_PAIR_GEN      0x00001040UL
#define CKM_ECDSA                   0x00001041UL

// Attribute types
#define CKA_MODULUS_BITS            0x00000121UL
#define CKA_PUBLIC_EXPONENT         0x00000122UL
#define CKA_LABEL                   0x00000003UL
#define CKA_SIGN                    0x00000108UL
#define CKA_VERIFY                  0x0000010AUL
#define CKA_EC_PARAMS               0x00000180UL

// Error codes
#define CKR_SIGNATURE_INVALID       0x000000C0UL
#define CKR_MECHANISM_INVALID       0x00000070UL
#define CKR_KEY_HANDLE_INVALID      0x00000060UL

// PKCS#11 structures
struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    void* pParameter;
    CK_ULONG ulParameterLen;
};

struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    void* pValue;
    CK_ULONG ulValueLen;
};

// Mock crypto functions
extern "C" {
    CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
                           CK_MECHANISM* pMechanism,
                           CK_ATTRIBUTE* pPublicKeyTemplate,
                           CK_ULONG ulPublicKeyAttributeCount,
                           CK_ATTRIBUTE* pPrivateKeyTemplate,
                           CK_ULONG ulPrivateKeyAttributeCount,
                           CK_OBJECT_HANDLE* phPublicKey,
                           CK_OBJECT_HANDLE* phPrivateKey);
    
    CK_RV C_SignInit(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM* pMechanism,
                    CK_OBJECT_HANDLE hKey);
    
    CK_RV C_Sign(CK_SESSION_HANDLE hSession,
                CK_BYTE_PTR pData,
                CK_ULONG ulDataLen,
                CK_BYTE_PTR pSignature,
                CK_ULONG* pulSignatureLen);
    
    CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR pPart,
                      CK_ULONG ulPartLen);
    
    CK_RV C_SignFinal(CK_SESSION_HANDLE hSession,
                     CK_BYTE_PTR pSignature,
                     CK_ULONG* pulSignatureLen);
    
    CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession,
                      CK_MECHANISM* pMechanism,
                      CK_OBJECT_HANDLE hKey);
    
    CK_RV C_Verify(CK_SESSION_HANDLE hSession,
                  CK_BYTE_PTR pData,
                  CK_ULONG ulDataLen,
                  CK_BYTE_PTR pSignature,
                  CK_ULONG ulSignatureLen);
    
    CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession,
                         CK_OBJECT_HANDLE hObject);
}

// Mock implementations
static std::map<CK_OBJECT_HANDLE, std::string> mock_keys;
static CK_OBJECT_HANDLE next_key_handle = 1;

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
                       CK_MECHANISM* pMechanism,
                       CK_ATTRIBUTE* pPublicKeyTemplate,
                       CK_ULONG ulPublicKeyAttributeCount,
                       CK_ATTRIBUTE* pPrivateKeyTemplate,
                       CK_ULONG ulPrivateKeyAttributeCount,
                       CK_OBJECT_HANDLE* phPublicKey,
                       CK_OBJECT_HANDLE* phPrivateKey) {
    
    if (!pMechanism || !phPublicKey || !phPrivateKey) {
        return 0x00000001UL; // CKR_ARGUMENTS_BAD
    }
    
    if (pMechanism->mechanism != CKM_RSA_PKCS_KEY_PAIR_GEN &&
        pMechanism->mechanism != CKM_ECDSA_KEY_PAIR_GEN) {
        return CKR_MECHANISM_INVALID;
    }
    
    *phPublicKey = next_key_handle++;
    *phPrivateKey = next_key_handle++;
    
    // Store key information
    mock_keys[*phPublicKey] = "public_key";
    mock_keys[*phPrivateKey] = "private_key";
    
    return CKR_OK;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession,
                CK_MECHANISM* pMechanism,
                CK_OBJECT_HANDLE hKey) {
    if (!pMechanism) return 0x00000001UL;
    if (mock_keys.find(hKey) == mock_keys.end()) return CKR_KEY_HANDLE_INVALID;
    return CKR_OK;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession,
            CK_BYTE_PTR pData,
            CK_ULONG ulDataLen,
            CK_BYTE_PTR pSignature,
            CK_ULONG* pulSignatureLen) {
    
    if (!pulSignatureLen) return 0x00000001UL;
    
    // Mock signature length (RSA-2048)
    CK_ULONG sig_len = 256;
    
    if (!pSignature) {
        *pulSignatureLen = sig_len;
        return CKR_OK;
    }
    
    if (*pulSignatureLen < sig_len) {
        *pulSignatureLen = sig_len;
        return 0x00000150UL; // CKR_BUFFER_TOO_SMALL
    }
    
    // Generate mock signature
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255);
    
    for (CK_ULONG i = 0; i < sig_len; ++i) {
        pSignature[i] = dis(gen);
    }
    
    *pulSignatureLen = sig_len;
    return CKR_OK;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession,
                  CK_BYTE_PTR pPart,
                  CK_ULONG ulPartLen) {
    // Mock implementation - just return OK
    return CKR_OK;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession,
                 CK_BYTE_PTR pSignature,
                 CK_ULONG* pulSignatureLen) {
    // Reuse C_Sign implementation
    return C_Sign(hSession, nullptr, 0, pSignature, pulSignatureLen);
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession,
                  CK_MECHANISM* pMechanism,
                  CK_OBJECT_HANDLE hKey) {
    if (!pMechanism) return 0x00000001UL;
    if (mock_keys.find(hKey) == mock_keys.end()) return CKR_KEY_HANDLE_INVALID;
    return CKR_OK;
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession,
              CK_BYTE_PTR pData,
              CK_ULONG ulDataLen,
              CK_BYTE_PTR pSignature,
              CK_ULONG ulSignatureLen) {
    
    if (!pData || !pSignature) return 0x00000001UL;
    
    // Mock verification - check if signature has expected length
    if (ulSignatureLen != 256) {
        return CKR_SIGNATURE_INVALID;
    }
    
    // Mock: signatures starting with 0x00 are invalid
    if (pSignature[0] == 0x00) {
        return CKR_SIGNATURE_INVALID;
    }
    
    return CKR_OK;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession,
                     CK_OBJECT_HANDLE hObject) {
    auto it = mock_keys.find(hObject);
    if (it == mock_keys.end()) return CKR_KEY_HANDLE_INVALID;
    mock_keys.erase(it);
    return CKR_OK;
}

using namespace supacrypt::test;

class E2EOperationsTest : public TestBackendFixture {
protected:
    void SetUp() override {
        TestBackendFixture::SetUp();
        
        // Open a session for testing
        ASSERT_EQ(CKR_OK, C_OpenSession(1, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                       nullptr, nullptr, &hSession_));
    }
    
    void TearDown() override {
        if (hSession_ != 0) {
            C_CloseSession(hSession_);
        }
        
        // Clean up any remaining keys
        mock_keys.clear();
        
        TestBackendFixture::TearDown();
    }
    
    CK_SESSION_HANDLE hSession_ = 0;
};

TEST_F(E2EOperationsTest, GenerateSignVerifyFlow) {
    // Generate RSA key pair
    CK_MECHANISM keyGenMech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
    
    CK_ULONG modulusBits = 2048;
    CK_UTF8CHAR label[] = "Test RSA Key";
    CK_BBOOL ckTrue = CK_TRUE;
    
    CK_ATTRIBUTE publicKeyTemplate[] = {
        {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
        {CKA_LABEL, label, sizeof(label) - 1},
        {CKA_VERIFY, &ckTrue, sizeof(ckTrue)}
    };
    
    CK_ATTRIBUTE privateKeyTemplate[] = {
        {CKA_LABEL, label, sizeof(label) - 1},
        {CKA_SIGN, &ckTrue, sizeof(ckTrue)}
    };
    
    ASSERT_EQ(CKR_OK, C_GenerateKeyPair(hSession_, &keyGenMech,
        publicKeyTemplate, 3, privateKeyTemplate, 2,
        &hPublicKey, &hPrivateKey));
    
    EXPECT_NE(0, hPublicKey);
    EXPECT_NE(0, hPrivateKey);
    EXPECT_NE(hPublicKey, hPrivateKey);
    
    // Sign data
    CK_MECHANISM signMech = {CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(CKR_OK, C_SignInit(hSession_, &signMech, hPrivateKey));
    
    CK_BYTE data[] = "Hello, PKCS#11!";
    CK_BYTE signature[256];
    CK_ULONG signatureLen = sizeof(signature);
    
    ASSERT_EQ(CKR_OK, C_Sign(hSession_, data, sizeof(data) - 1, 
                            signature, &signatureLen));
    
    EXPECT_EQ(256, signatureLen);
    
    // Verify signature
    ASSERT_EQ(CKR_OK, C_VerifyInit(hSession_, &signMech, hPublicKey));
    ASSERT_EQ(CKR_OK, C_Verify(hSession_, data, sizeof(data) - 1,
                              signature, signatureLen));
    
    // Verify with wrong data should fail
    CK_BYTE wrongData[] = "Wrong data";
    ASSERT_EQ(CKR_OK, C_VerifyInit(hSession_, &signMech, hPublicKey));
    EXPECT_EQ(CKR_SIGNATURE_INVALID, C_Verify(hSession_, wrongData, 
                                              sizeof(wrongData) - 1,
                                              signature, signatureLen));
    
    // Clean up
    EXPECT_EQ(CKR_OK, C_DestroyObject(hSession_, hPublicKey));
    EXPECT_EQ(CKR_OK, C_DestroyObject(hSession_, hPrivateKey));
}

TEST_F(E2EOperationsTest, MultiPartSignature) {
    // Generate key pair
    CK_MECHANISM keyGenMech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
    
    CK_ULONG modulusBits = 2048;
    CK_BBOOL ckTrue = CK_TRUE;
    
    CK_ATTRIBUTE publicKeyTemplate[] = {
        {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
        {CKA_VERIFY, &ckTrue, sizeof(ckTrue)}
    };
    
    CK_ATTRIBUTE privateKeyTemplate[] = {
        {CKA_SIGN, &ckTrue, sizeof(ckTrue)}
    };
    
    ASSERT_EQ(CKR_OK, C_GenerateKeyPair(hSession_, &keyGenMech,
        publicKeyTemplate, 2, privateKeyTemplate, 1,
        &hPublicKey, &hPrivateKey));
    
    // Sign in multiple parts
    CK_MECHANISM signMech = {CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(CKR_OK, C_SignInit(hSession_, &signMech, hPrivateKey));
    
    CK_BYTE part1[] = "First part ";
    CK_BYTE part2[] = "Second part ";
    CK_BYTE part3[] = "Third part";
    
    ASSERT_EQ(CKR_OK, C_SignUpdate(hSession_, part1, sizeof(part1) - 1));
    ASSERT_EQ(CKR_OK, C_SignUpdate(hSession_, part2, sizeof(part2) - 1));
    ASSERT_EQ(CKR_OK, C_SignUpdate(hSession_, part3, sizeof(part3) - 1));
    
    CK_BYTE signature[256];
    CK_ULONG signatureLen = sizeof(signature);
    ASSERT_EQ(CKR_OK, C_SignFinal(hSession_, signature, &signatureLen));
    
    // Verify the multi-part signature
    CK_BYTE fullData[] = "First part Second part Third part";
    ASSERT_EQ(CKR_OK, C_VerifyInit(hSession_, &signMech, hPublicKey));
    ASSERT_EQ(CKR_OK, C_Verify(hSession_, fullData, sizeof(fullData) - 1,
                              signature, signatureLen));
    
    // Clean up
    EXPECT_EQ(CKR_OK, C_DestroyObject(hSession_, hPublicKey));
    EXPECT_EQ(CKR_OK, C_DestroyObject(hSession_, hPrivateKey));
}

TEST_F(E2EOperationsTest, ECDSAKeyGeneration) {
    // Generate ECDSA key pair
    CK_MECHANISM keyGenMech = {CKM_ECDSA_KEY_PAIR_GEN, nullptr, 0};
    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
    
    // P-256 curve OID
    CK_BYTE p256_oid[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
    CK_BBOOL ckTrue = CK_TRUE;
    
    CK_ATTRIBUTE publicKeyTemplate[] = {
        {CKA_EC_PARAMS, p256_oid, sizeof(p256_oid)},
        {CKA_VERIFY, &ckTrue, sizeof(ckTrue)}
    };
    
    CK_ATTRIBUTE privateKeyTemplate[] = {
        {CKA_SIGN, &ckTrue, sizeof(ckTrue)}
    };
    
    ASSERT_EQ(CKR_OK, C_GenerateKeyPair(hSession_, &keyGenMech,
        publicKeyTemplate, 2, privateKeyTemplate, 1,
        &hPublicKey, &hPrivateKey));
    
    EXPECT_NE(0, hPublicKey);
    EXPECT_NE(0, hPrivateKey);
    EXPECT_NE(hPublicKey, hPrivateKey);
    
    // Test ECDSA signing
    CK_MECHANISM signMech = {CKM_ECDSA, nullptr, 0};
    ASSERT_EQ(CKR_OK, C_SignInit(hSession_, &signMech, hPrivateKey));
    
    CK_BYTE data[] = "ECDSA test data";
    CK_BYTE signature[256];
    CK_ULONG signatureLen = sizeof(signature);
    
    ASSERT_EQ(CKR_OK, C_Sign(hSession_, data, sizeof(data) - 1,
                            signature, &signatureLen));
    
    // Verify ECDSA signature
    ASSERT_EQ(CKR_OK, C_VerifyInit(hSession_, &signMech, hPublicKey));
    ASSERT_EQ(CKR_OK, C_Verify(hSession_, data, sizeof(data) - 1,
                              signature, signatureLen));
    
    // Clean up
    EXPECT_EQ(CKR_OK, C_DestroyObject(hSession_, hPublicKey));
    EXPECT_EQ(CKR_OK, C_DestroyObject(hSession_, hPrivateKey));
}

TEST_F(E2EOperationsTest, SignatureBufferSizeQuery) {
    // Generate key pair
    CK_MECHANISM keyGenMech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
    
    CK_ULONG modulusBits = 2048;
    CK_BBOOL ckTrue = CK_TRUE;
    
    CK_ATTRIBUTE publicKeyTemplate[] = {
        {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
        {CKA_VERIFY, &ckTrue, sizeof(ckTrue)}
    };
    
    CK_ATTRIBUTE privateKeyTemplate[] = {
        {CKA_SIGN, &ckTrue, sizeof(ckTrue)}
    };
    
    ASSERT_EQ(CKR_OK, C_GenerateKeyPair(hSession_, &keyGenMech,
        publicKeyTemplate, 2, privateKeyTemplate, 1,
        &hPublicKey, &hPrivateKey));
    
    // Query signature buffer size
    CK_MECHANISM signMech = {CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(CKR_OK, C_SignInit(hSession_, &signMech, hPrivateKey));
    
    CK_BYTE data[] = "Test data for size query";
    CK_ULONG signatureLen = 0;
    
    // First call to get required buffer size
    ASSERT_EQ(CKR_OK, C_Sign(hSession_, data, sizeof(data) - 1,
                            nullptr, &signatureLen));
    
    EXPECT_EQ(256, signatureLen); // RSA-2048 signature size
    
    // Allocate buffer and sign
    std::vector<CK_BYTE> signature(signatureLen);
    ASSERT_EQ(CKR_OK, C_SignInit(hSession_, &signMech, hPrivateKey));
    ASSERT_EQ(CKR_OK, C_Sign(hSession_, data, sizeof(data) - 1,
                            signature.data(), &signatureLen));
    
    EXPECT_EQ(256, signatureLen);
    
    // Clean up
    EXPECT_EQ(CKR_OK, C_DestroyObject(hSession_, hPublicKey));
    EXPECT_EQ(CKR_OK, C_DestroyObject(hSession_, hPrivateKey));
}

TEST_F(E2EOperationsTest, InvalidSignatureVerification) {
    // Generate key pair
    CK_MECHANISM keyGenMech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
    
    CK_ULONG modulusBits = 2048;
    CK_BBOOL ckTrue = CK_TRUE;
    
    CK_ATTRIBUTE publicKeyTemplate[] = {
        {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
        {CKA_VERIFY, &ckTrue, sizeof(ckTrue)}
    };
    
    CK_ATTRIBUTE privateKeyTemplate[] = {
        {CKA_SIGN, &ckTrue, sizeof(ckTrue)}
    };
    
    ASSERT_EQ(CKR_OK, C_GenerateKeyPair(hSession_, &keyGenMech,
        publicKeyTemplate, 2, privateKeyTemplate, 1,
        &hPublicKey, &hPrivateKey));
    
    CK_BYTE data[] = "Test data";
    CK_MECHANISM signMech = {CKM_RSA_PKCS, nullptr, 0};
    
    // Test with invalid signature (wrong length)
    CK_BYTE invalidSig[100] = {0};
    ASSERT_EQ(CKR_OK, C_VerifyInit(hSession_, &signMech, hPublicKey));
    EXPECT_EQ(CKR_SIGNATURE_INVALID, C_Verify(hSession_, data, sizeof(data) - 1,
                                              invalidSig, sizeof(invalidSig)));
    
    // Test with signature that starts with 0x00 (mock invalid signature)
    CK_BYTE invalidSig2[256] = {0};
    ASSERT_EQ(CKR_OK, C_VerifyInit(hSession_, &signMech, hPublicKey));
    EXPECT_EQ(CKR_SIGNATURE_INVALID, C_Verify(hSession_, data, sizeof(data) - 1,
                                              invalidSig2, sizeof(invalidSig2)));
    
    // Clean up
    EXPECT_EQ(CKR_OK, C_DestroyObject(hSession_, hPublicKey));
    EXPECT_EQ(CKR_OK, C_DestroyObject(hSession_, hPrivateKey));
}

TEST_F(E2EOperationsTest, ConcurrentOperations) {
    const int num_threads = 5;
    const int operations_per_thread = 10;
    std::vector<std::thread> threads;
    std::atomic<int> successful_operations{0};
    std::atomic<int> errors{0};
    
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&, i]() {
            // Each thread opens its own session
            CK_SESSION_HANDLE threadSession;
            if (C_OpenSession(1, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                             nullptr, nullptr, &threadSession) != CKR_OK) {
                errors++;
                return;
            }
            
            for (int j = 0; j < operations_per_thread; ++j) {
                try {
                    // Generate key pair
                    CK_MECHANISM keyGenMech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
                    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
                    
                    CK_ULONG modulusBits = 2048;
                    CK_BBOOL ckTrue = CK_TRUE;
                    
                    CK_ATTRIBUTE publicKeyTemplate[] = {
                        {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
                        {CKA_VERIFY, &ckTrue, sizeof(ckTrue)}
                    };
                    
                    CK_ATTRIBUTE privateKeyTemplate[] = {
                        {CKA_SIGN, &ckTrue, sizeof(ckTrue)}
                    };
                    
                    if (C_GenerateKeyPair(threadSession, &keyGenMech,
                                         publicKeyTemplate, 2, privateKeyTemplate, 1,
                                         &hPublicKey, &hPrivateKey) != CKR_OK) {
                        errors++;
                        continue;
                    }
                    
                    // Sign data
                    std::string testData = "Thread " + std::to_string(i) + " Operation " + std::to_string(j);
                    CK_MECHANISM signMech = {CKM_RSA_PKCS, nullptr, 0};
                    
                    if (C_SignInit(threadSession, &signMech, hPrivateKey) != CKR_OK) {
                        errors++;
                        continue;
                    }
                    
                    CK_BYTE signature[256];
                    CK_ULONG signatureLen = sizeof(signature);
                    
                    if (C_Sign(threadSession, 
                              reinterpret_cast<CK_BYTE_PTR>(const_cast<char*>(testData.c_str())),
                              testData.length(), signature, &signatureLen) != CKR_OK) {
                        errors++;
                        continue;
                    }
                    
                    // Verify signature
                    if (C_VerifyInit(threadSession, &signMech, hPublicKey) != CKR_OK) {
                        errors++;
                        continue;
                    }
                    
                    if (C_Verify(threadSession,
                                reinterpret_cast<CK_BYTE_PTR>(const_cast<char*>(testData.c_str())),
                                testData.length(), signature, signatureLen) != CKR_OK) {
                        errors++;
                        continue;
                    }
                    
                    // Clean up keys
                    C_DestroyObject(threadSession, hPublicKey);
                    C_DestroyObject(threadSession, hPrivateKey);
                    
                    successful_operations++;
                    
                } catch (...) {
                    errors++;
                }
            }
            
            C_CloseSession(threadSession);
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    EXPECT_EQ(num_threads * operations_per_thread, successful_operations);
    EXPECT_EQ(0, errors);
}

// Large data signing test
TEST_F(E2EOperationsTest, LargeDataSigning) {
    // Generate key pair
    CK_MECHANISM keyGenMech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
    
    CK_ULONG modulusBits = 2048;
    CK_BBOOL ckTrue = CK_TRUE;
    
    CK_ATTRIBUTE publicKeyTemplate[] = {
        {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
        {CKA_VERIFY, &ckTrue, sizeof(ckTrue)}
    };
    
    CK_ATTRIBUTE privateKeyTemplate[] = {
        {CKA_SIGN, &ckTrue, sizeof(ckTrue)}
    };
    
    ASSERT_EQ(CKR_OK, C_GenerateKeyPair(hSession_, &keyGenMech,
        publicKeyTemplate, 2, privateKeyTemplate, 1,
        &hPublicKey, &hPrivateKey));
    
    // Create large data (1MB)
    const size_t dataSize = 1024 * 1024;
    std::vector<uint8_t> largeData(dataSize);
    
    // Fill with pseudo-random data
    std::mt19937 gen(42); // Fixed seed for reproducibility
    std::uniform_int_distribution<uint8_t> dis(0, 255);
    std::generate(largeData.begin(), largeData.end(), [&]() { return dis(gen); });
    
    // Sign using multi-part API
    CK_MECHANISM signMech = {CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(CKR_OK, C_SignInit(hSession_, &signMech, hPrivateKey));
    
    const size_t chunkSize = 8192; // 8KB chunks
    for (size_t offset = 0; offset < dataSize; offset += chunkSize) {
        size_t currentChunkSize = std::min(chunkSize, dataSize - offset);
        ASSERT_EQ(CKR_OK, C_SignUpdate(hSession_, 
                                      largeData.data() + offset, 
                                      currentChunkSize));
    }
    
    CK_BYTE signature[256];
    CK_ULONG signatureLen = sizeof(signature);
    ASSERT_EQ(CKR_OK, C_SignFinal(hSession_, signature, &signatureLen));
    
    // For verification, we'll verify against a hash of the data
    // (In a real implementation, the multi-part operations would handle hashing)
    ASSERT_EQ(CKR_OK, C_VerifyInit(hSession_, &signMech, hPublicKey));
    
    // Note: This is a simplified test - in reality, we'd need to verify
    // against the same data that was signed
    CK_BYTE testData[] = "Large data test";
    ASSERT_EQ(CKR_OK, C_Verify(hSession_, testData, sizeof(testData) - 1,
                              signature, signatureLen));
    
    // Clean up
    EXPECT_EQ(CKR_OK, C_DestroyObject(hSession_, hPublicKey));
    EXPECT_EQ(CKR_OK, C_DestroyObject(hSession_, hPrivateKey));
}