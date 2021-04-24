cmake_minimum_required(VERSION 3.0.0)
project(azure VERSION 0.1.0)

include(CTest)
enable_testing()

add_executable(azure main.cpp sign.cpp)

set(CMAKE_CXX_FLAGS -std=c++14)

link_directories(/usr/local)
target_link_libraries(azure pthread curl crypto)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
