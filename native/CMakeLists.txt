cmake_minimum_required(VERSION 3.9)
project(ecelgamal)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/include /Library/Java/JavaVirtualMachines/jdk1.8.0_151.jdk/Contents/Home/include /Library/Java/JavaVirtualMachines/jdk1.8.0_151.jdk/Contents/Home/include/darwin)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/out)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY  ${CMAKE_CURRENT_SOURCE_DIR}/out)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")

add_executable(ecelgamal testing.cpp ecelgamal.h ecelgamal.c crtecelgamal.c crtecelgamal.h)
add_library(ecelgamal-lib SHARED ecelgamal.h ecelgamal.c crtecelgamal.c crtecelgamal.h)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../src/main/resources)
add_library(ecelgamal-jni-wrapper SHARED crtecelgamal_jni_wrapper.c ecelgamal.h ecelgamal.c)


target_link_libraries(ecelgamal crypto ssl)
target_link_libraries(ecelgamal-jni-wrapper crypto ssl)
target_link_libraries(ecelgamal-lib  crypto ssl)