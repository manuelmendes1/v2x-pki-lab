cmake_minimum_required(VERSION 3.16)
project(v2x_standard_v3_issuer LANGUAGES CXX)

find_package(Vanetza CONFIG REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_executable(standard-v3-issuer main.cpp)
target_compile_features(standard-v3-issuer PRIVATE cxx_std_17)
target_compile_options(standard-v3-issuer PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(standard-v3-issuer PRIVATE Vanetza::security OpenSSL::Crypto)

# The source also contains a compile-time guard against the experimental profile.
