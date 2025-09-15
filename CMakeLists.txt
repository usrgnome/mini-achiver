cmake_minimum_required(VERSION 3.10)
project(mfa_reader C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(mfa_read
    src/main.c
    src/util.c
)

target_include_directories(mfa_read PRIVATE ${CMAKE_SOURCE_DIR}/include)

if(MSVC)
  target_compile_options(mfa_read PRIVATE /W4 /WX-)
else()
  target_compile_options(mfa_read PRIVATE -Wall -Wextra -Wpedantic)
endif()
