cmake_minimum_required(VERSION 3.5)
project(airdroidserver)

set(CMAKE_CXX_STANDARD 11)

include_directories(/opt/homebrew/include)

add_executable(airdroidserver main.cpp)