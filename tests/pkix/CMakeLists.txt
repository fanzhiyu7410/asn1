# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

asn1_add_test(test_pkix_certificate test_pkix_certificate.c)
target_link_libraries(test_pkix_certificate PRIVATE asn1_test_support)

# 独立消费只验证本次实际构建出的链接形态。
set(ASN1_PKIX_LINK_MODES "")
if(TARGET asn1::pkix::shared)
  list(APPEND ASN1_PKIX_LINK_MODES shared)
endif()
if(TARGET asn1::pkix::static)
  list(APPEND ASN1_PKIX_LINK_MODES static)
endif()
string(REPLACE ";" "," ASN1_PKIX_LINK_MODES_ARG "${ASN1_PKIX_LINK_MODES}")

add_test(
  NAME test_pkix_consumer
  COMMAND
    ${CMAKE_COMMAND}
    -DASN1_PKIX_BUILD_DIR=${CMAKE_BINARY_DIR}
    -DASN1_PKIX_WORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/consumer-work
    -DASN1_PKIX_CONFIG=$<CONFIG>
    -DASN1_PKIX_GENERATOR=${CMAKE_GENERATOR}
    -DASN1_PKIX_GENERATOR_PLATFORM=${CMAKE_GENERATOR_PLATFORM}
    -DASN1_PKIX_C_COMPILER=${CMAKE_C_COMPILER}
    -DASN1_PKIX_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DASN1_PKIX_LINK_MODES=${ASN1_PKIX_LINK_MODES_ARG}
    -DASN1_PKIX_C_FLAGS=${CMAKE_C_FLAGS}
    -DASN1_PKIX_CXX_FLAGS=${CMAKE_CXX_FLAGS}
    -DASN1_PKIX_EXE_LINKER_FLAGS=${CMAKE_EXE_LINKER_FLAGS}
    -DASN1_PKIX_CERT_PATH=${CMAKE_SOURCE_DIR}/tests/data/cert_rsa_selfsigned.der
    -P ${CMAKE_CURRENT_SOURCE_DIR}/test_pkix_consumer.cmake
)
set_tests_properties(test_pkix_consumer PROPERTIES TIMEOUT 300)

if(TARGET asn1::pkix::static)
  target_link_libraries(test_pkix_certificate PRIVATE asn1::pkix::static)
else()
  target_link_libraries(test_pkix_certificate PRIVATE asn1::pkix::shared)
  if(WIN32)
    add_custom_command(
      TARGET test_pkix_certificate POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:asn1::pkix::shared>
        $<TARGET_FILE_DIR:test_pkix_certificate>
    )
  endif()
endif()
