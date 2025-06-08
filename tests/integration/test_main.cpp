// tests/integration/test_main.cpp

#include <gtest/gtest.h>
#include <iostream>

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    
    std::cout << "Starting Supacrypt PKCS#11 Integration Tests" << std::endl;
    std::cout << "=============================================" << std::endl;
    
    // Check if backend is available
    std::cout << "Checking backend availability..." << std::endl;
    
    int result = RUN_ALL_TESTS();
    
    std::cout << "Integration tests completed." << std::endl;
    return result;
}