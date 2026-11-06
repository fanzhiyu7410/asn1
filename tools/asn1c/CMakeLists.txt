# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

# asn1c：`.asn1` 文本解析、语义校验与描述表生成工具。
# 工具内部静态库只在本目录使用，不链接核心库或模块。
cmake_minimum_required(VERSION 3.20)

project(
  asn1c
  VERSION 0.1.0
  DESCRIPTION "ASN.1 模块文本解析与描述表生成工具"
  LANGUAGES CXX
)

# 独立版本头：只由本目录的 project VERSION 派生，不安装到消费者。
set(asn1c_generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated/include")
file(MAKE_DIRECTORY "${asn1c_generated_dir}")

configure_file(
  "${asn1_SOURCE_DIR}/cmake/asn1cVersion.h.in"
  "${asn1c_generated_dir}/asn1c_version.h"
  @ONLY
)

asn1_assert_generated_version_header(
  "${asn1c_generated_dir}/asn1c_version.h"
  "${PROJECT_VERSION_MAJOR}" "${PROJECT_VERSION_MINOR}"
  "${PROJECT_VERSION_PATCH}" "${PROJECT_VERSION}" "ASN1C")

add_library(asn1c_lib STATIC
  src/crc32c.cpp
  src/diag.cpp
  src/lexer.cpp
  src/parser.cpp
  src/semantic.cpp
  src/table.cpp
)
target_include_directories(asn1c_lib PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
asn1_apply_common_settings(asn1c_lib)

add_executable(asn1c src/main.cpp)
target_link_libraries(asn1c PRIVATE asn1c_lib)
target_include_directories(asn1c PRIVATE
  "${asn1c_generated_dir}"
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
)
asn1_apply_common_settings(asn1c)

install(TARGETS asn1c RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
