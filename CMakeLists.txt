cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

#run asn1c to generate asn1c files
# find_package(asn1c REQUIRED)
execute_process(COMMAND asn1c ${CMAKE_SOURCE_DIR}/xtt_keypair.asn1)
execute_process(COMMAND rm converter-example.c)
file(GLOB generated_sources ${CMAKE_CURRENT_BINARY_DIR}/*.c)

set(PDU "Keypair")
option(DISABLE_OER "Build with OER Support" OFF)

set( ASN1_SRCS  ${CMAKE_SOURCE_DIR}/main.c
                ${generated_sources})

add_executable(xtt_keypair ${ASN1_SRCS})
target_include_directories(xtt_keypair PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
add_compile_options(-DPDU=Keypair -DASN_DISABLE_OER_SUPPORT=${DISABLE_OER})
#rm converter-example

#run cc -I. -o createkeypair *.c -DPDU=Keypair -DASN_DISABLE_OER_SUPPORT=OFF
