# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

asn1_add_test(test_pkix_certificate test_pkix_certificate.c)
target_link_libraries(test_pkix_certificate PRIVATE asn1_test_support)

# 独立消费由 tests/consumer 的通用用例覆盖（含安装前缀重定位）。

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
