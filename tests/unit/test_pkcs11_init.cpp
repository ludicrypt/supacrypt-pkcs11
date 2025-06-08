/**
 * @file test_pkcs11_init.cpp
 * @brief Tests for PKCS#11 initialization functions
 */

#include <gtest/gtest.h>
#include "supacrypt/pkcs11/pkcs11.h"
#include "supacrypt/pkcs11/supacrypt_pkcs11.h"

class PKCS11InitTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Ensure clean state before each test
        C_Finalize(nullptr);
    }
    
    void TearDown() override {
        // Cleanup after each test
        C_Finalize(nullptr);
    }
};

TEST_F(PKCS11InitTest, InitializeSuccess) {
    CK_RV rv = C_Initialize(nullptr);
    EXPECT_EQ(rv, CKR_OK);
}

TEST_F(PKCS11InitTest, InitializeTwice) {
    CK_RV rv = C_Initialize(nullptr);
    EXPECT_EQ(rv, CKR_OK);
    
    rv = C_Initialize(nullptr);
    EXPECT_EQ(rv, CKR_CRYPTOKI_ALREADY_INITIALIZED);
}

TEST_F(PKCS11InitTest, FinalizeNotInitialized) {
    CK_RV rv = C_Finalize(nullptr);
    EXPECT_EQ(rv, CKR_CRYPTOKI_NOT_INITIALIZED);
}

TEST_F(PKCS11InitTest, FinalizeWithBadArgs) {
    C_Initialize(nullptr);
    
    void* dummy = reinterpret_cast<void*>(0x1234);
    CK_RV rv = C_Finalize(dummy);
    EXPECT_EQ(rv, CKR_ARGUMENTS_BAD);
}

TEST_F(PKCS11InitTest, GetInfoNotInitialized) {
    CK_INFO info;
    CK_RV rv = C_GetInfo(&info);
    EXPECT_EQ(rv, CKR_CRYPTOKI_NOT_INITIALIZED);
}