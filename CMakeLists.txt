cmake_minimum_required(VERSION 3.16)
project(HelloWorld)

# C++ 표준 설정
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 실행 파일 생성
add_executable(HelloWorld main.cpp)