cmake_minimum_required(VERSION 3.15)

project(SHA256)

add_library(sha256 ${PROJECT_SOURCE_DIR}/src/SHA256.cpp)

add_executable(SHA256 ${PROJECT_SOURCE_DIR}/src/main.cpp)

include_directories(include)

target_link_libraries(SHA256 sha256)