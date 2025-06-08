// tests/benchmarks/benchmark_main.cpp

#include <benchmark/benchmark.h>
#include <iostream>

int main(int argc, char** argv) {
    std::cout << "Supacrypt PKCS#11 Performance Benchmarks" << std::endl;
    std::cout << "=========================================" << std::endl;
    
    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv)) {
        return 1;
    }
    
    ::benchmark::RunSpecifiedBenchmarks();
    ::benchmark::Shutdown();
    
    return 0;
}