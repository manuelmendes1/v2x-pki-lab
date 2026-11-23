cmake_minimum_required(VERSION 3.16)
project(v2x_standard_v3_validator_test LANGUAGES CXX)

find_package(Vanetza CONFIG REQUIRED)

add_executable(standard-v3-validator-test main.cpp)

target_compile_features(standard-v3-validator-test PRIVATE cxx_std_17)
target_compile_options(standard-v3-validator-test PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

set(VANETZA_LINK_TARGETS Vanetza::security)

if(TARGET Vanetza::common)
    list(APPEND VANETZA_LINK_TARGETS Vanetza::common)
endif()

if(TARGET Vanetza::vanetza_common)
    list(APPEND VANETZA_LINK_TARGETS Vanetza::vanetza_common)
endif()

target_link_libraries(standard-v3-validator-test PRIVATE
    ${VANETZA_LINK_TARGETS}
)
