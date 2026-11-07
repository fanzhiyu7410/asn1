# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

# 模块 open/close 成本基线（ASN1_BUILD_BENCHMARKS=ON 时构建，不进 CTest）。

if(NOT (TARGET asn1::pkix::static OR TARGET asn1::pkix::shared))
  message(STATUS "asn1-pkix 未构建，跳过模块基准")
  return()
endif()
if(NOT (TARGET asn1::pkcs::static OR TARGET asn1::pkcs::shared))
  message(STATUS "asn1-pkcs 未构建，跳过模块基准")
  return()
endif()
if(NOT (TARGET asn1::cms::static OR TARGET asn1::cms::shared))
  message(STATUS "asn1-cms 未构建，跳过模块基准")
  return()
endif()

set(ASN1_BENCH_USE_STATIC ON)
foreach(module core pkix pkcs cms)
  if(module STREQUAL "core")
    if(NOT TARGET asn1::static)
      set(ASN1_BENCH_USE_STATIC OFF)
    endif()
  elseif(NOT TARGET asn1::${module}::static)
    set(ASN1_BENCH_USE_STATIC OFF)
  endif()
endforeach()

add_executable(bench_module_open bench_module_open.c)
set_target_properties(
  bench_module_open
  PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
    LINKER_LANGUAGE CXX
)
target_compile_definitions(
  bench_module_open PRIVATE
  ASN1_BENCH_DATA_DIR="${CMAKE_SOURCE_DIR}/tests/data"
)
if(MSVC)
  target_compile_options(bench_module_open PRIVATE /utf-8)
endif()

if(ASN1_BENCH_USE_STATIC)
  target_link_libraries(
    bench_module_open PRIVATE
    asn1::static
    asn1::pkix::static
    asn1::pkcs::static
    asn1::cms::static
  )
else()
  target_link_libraries(
    bench_module_open PRIVATE
    asn1::shared
    asn1::pkix::shared
    asn1::pkcs::shared
    asn1::cms::shared
  )
  if(WIN32)
    foreach(target asn1::shared asn1::pkix::shared asn1::pkcs::shared
            asn1::cms::shared)
      add_custom_command(
        TARGET bench_module_open POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
          $<TARGET_FILE:${target}> $<TARGET_FILE_DIR:bench_module_open>
      )
    endforeach()
  endif()
endif()
