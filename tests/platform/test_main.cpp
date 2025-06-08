// tests/platform/test_main.cpp

#include <gtest/gtest.h>
#include <iostream>

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    
    std::cout << "Starting Supacrypt PKCS#11 Platform-Specific Tests" << std::endl;
    std::cout << "==================================================" << std::endl;
    
#ifdef _WIN32
    std::cout << "Platform: Windows" << std::endl;
#elif __APPLE__
    std::cout << "Platform: macOS" << std::endl;
#elif __linux__
    std::cout << "Platform: Linux" << std::endl;
#else
    std::cout << "Platform: Unknown" << std::endl;
#endif
    
    int result = RUN_ALL_TESTS();
    
    std::cout << "Platform tests completed." << std::endl;
    return result;
}