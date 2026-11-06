# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

asn1_add_test(test_cms_structures test_cms_structures.c)
target_link_libraries(test_cms_structures PRIVATE asn1_test_support)

asn1_add_test(test_cms_builder test_cms_builder.c)
target_link_libraries(test_cms_builder PRIVATE asn1_test_support)

if(TARGET asn1::cms::static)
  target_link_libraries(test_cms_structures PRIVATE asn1::cms::static)
  target_link_libraries(test_cms_builder PRIVATE asn1::cms::static)
else()
  target_link_libraries(test_cms_structures PRIVATE asn1::cms::shared)
  target_link_libraries(test_cms_builder PRIVATE asn1::cms::shared)
  if(WIN32)
    add_custom_command(
      TARGET test_cms_structures POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:asn1::cms::shared>
        $<TARGET_FILE_DIR:test_cms_structures>
    )
    add_custom_command(
      TARGET test_cms_builder POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:asn1::cms::shared>
        $<TARGET_FILE_DIR:test_cms_builder>
    )
  endif()
endif()
