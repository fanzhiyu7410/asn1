# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

# 可选基准（ASN1_BUILD_BENCHMARKS=ON 时构建），不注册到 CTest 主流程。

if(NOT TARGET asn1::pkix::static AND NOT TARGET asn1::pkix::shared)
  message(STATUS "asn1-pkix 未构建，跳过基准")
  return()
endif()

add_executable(asn1_pkix_bench pkix_bench.c)
set_target_properties(asn1_pkix_bench PROPERTIES C_STANDARD 99
                                                 C_STANDARD_REQUIRED ON)
if(MSVC)
  target_compile_options(asn1_pkix_bench PRIVATE /utf-8)
endif()

if(TARGET asn1::pkix::static)
  target_link_libraries(asn1_pkix_bench PRIVATE asn1::pkix::static)
else()
  target_link_libraries(asn1_pkix_bench PRIVATE asn1::pkix::shared)
  if(WIN32)
    add_custom_command(
      TARGET asn1_pkix_bench POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:asn1::pkix::shared> $<TARGET_FILE_DIR:asn1_pkix_bench>
    )
    add_custom_command(
      TARGET asn1_pkix_bench POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:asn1::shared> $<TARGET_FILE_DIR:asn1_pkix_bench>
    )
  endif()
endif()
