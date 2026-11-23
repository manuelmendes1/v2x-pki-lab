cmake_minimum_required(VERSION 3.16)
project(v2x_standard_v3_geographic_validator LANGUAGES CXX)

find_package(Vanetza CONFIG REQUIRED)

add_executable(standard-v3-geographic-validator main.cpp)

target_compile_features(standard-v3-geographic-validator PRIVATE cxx_std_17)

target_compile_options(standard-v3-geographic-validator PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

target_link_libraries(standard-v3-geographic-validator PRIVATE
    Vanetza::security
)
