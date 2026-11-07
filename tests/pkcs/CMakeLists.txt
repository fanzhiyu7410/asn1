# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

set(ASN1_PKCS_TESTS
  test_pkcs_structures
  test_pkcs12_structures
)

foreach(test_name IN LISTS ASN1_PKCS_TESTS)
  asn1_add_test(${test_name} ${test_name}.c)
  target_link_libraries(${test_name} PRIVATE asn1_test_support)

  if(TARGET asn1::pkcs::static)
    target_link_libraries(${test_name} PRIVATE asn1::pkcs::static)
  else()
    target_link_libraries(${test_name} PRIVATE asn1::pkcs::shared)
    if(WIN32)
      add_custom_command(
        TARGET ${test_name} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
          $<TARGET_FILE:asn1::pkcs::shared>
          $<TARGET_FILE_DIR:${test_name}>
      )
    endif()
  endif()
endforeach()
