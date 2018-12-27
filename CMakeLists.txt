cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

execute_process(COMMAND asn1c ${CMAKE_SOURCE_DIR}/xtt_keypair.asn1)
execute_process(COMMAND rm converter-example.c)
file(GLOB generated_sources ${CMAKE_CURRENT_BINARY_DIR}/*.c)

set(PDU "Keypair")
option(DISABLE_OER "Build with OER Support" OFF)

set(ASN1_SRCS  ${CMAKE_SOURCE_DIR}/main.c
               ${generated_sources})

add_executable(createkeypair ${ASN1_SRCS})
target_include_directories(createkeypair PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
add_compile_options(-DPDU=${PDU} -DASN_DISABLE_OER_SUPPORT=${DISABLE_OER})
