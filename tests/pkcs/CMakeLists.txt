# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

asn1_add_test(test_pkcs_structures test_pkcs_structures.c)
target_link_libraries(test_pkcs_structures PRIVATE asn1_test_support)

if(TARGET asn1::pkcs::static)
  target_link_libraries(test_pkcs_structures PRIVATE asn1::pkcs::static)
else()
  target_link_libraries(test_pkcs_structures PRIVATE asn1::pkcs::shared)
  if(WIN32)
    add_custom_command(
      TARGET test_pkcs_structures POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:asn1::pkcs::shared>
        $<TARGET_FILE_DIR:test_pkcs_structures>
    )
  endif()
endif()
