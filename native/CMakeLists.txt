cmake_minimum_required(VERSION 3.5)
project(ecelgamal)

set(DO_STATIC  FALSE)
set(PATH_STATIC /usr/local/Cellar/openssl@1.1/1.1.0g_1)

find_package(Java REQUIRED)
find_package(JNI REQUIRED)

if(${DO_STATIC})
    INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/include ${PATH_STATIC}/include)
    set(NEW_SSL_1  ${PATH_STATIC}/lib/libssl.a)
    set(NEW_SSL_2  ${PATH_STATIC}/lib/libcrypto.a)
else()
    find_package(OpenSSL REQUIRED)
    message(${OPENSSL_VERSION})
    INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/include)
    set(NEW_SSL_1  crypto)
    set(NEW_SSL_2  ssl)
endif()

file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/out)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/out)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY  ${CMAKE_CURRENT_SOURCE_DIR}/out)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -std=c++11")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")

add_executable(ecelgamal testing.cpp ecelgamal.h ecelgamal.c crtecelgamal.c crtecelgamal.h)
add_library(ecelgamal-lib SHARED ecelgamal.h ecelgamal.c crtecelgamal.c crtecelgamal.h)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/include ${JNI_INCLUDE_DIRS})
add_library(ecelgamal-jni-wrapper SHARED crtecelgamal_jni_wrapper.c ecelgamal.h ecelgamal.c)


target_link_libraries(ecelgamal ${NEW_SSL_1} ${NEW_SSL_2})
target_link_libraries(ecelgamal-jni-wrapper ${NEW_SSL_1} ${NEW_SSL_2})
target_link_libraries(ecelgamal-lib  ${NEW_SSL_1} ${NEW_SSL_2})
