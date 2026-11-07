# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.20)

project(
  asn1
  VERSION 0.1.0
  DESCRIPTION "跨平台 ASN.1 解析与编解码库（C ABI 对外，C++ 内部实现）"
  LANGUAGES C CXX
)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(GNUInstallDirs)
include(Asn1Options)
include(Asn1CompilerChecks)
include(Asn1Module)
include(Asn1Version)

asn1_generate_core_version_header()

add_subdirectory(src)

# 工具先于模块配置：模块可选地在构建期调用 asn1c 重新生成描述表。
if(ASN1_BUILD_TOOLS)
  add_subdirectory(tools)
endif()

if(ASN1_BUILD_MODULES)
  add_subdirectory(modules)
endif()

if(ASN1_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if(ASN1_BUILD_BENCHMARKS)
  add_subdirectory(benchmarks)
  add_subdirectory(tests/bench)
endif()

if(ASN1_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# 嵌入式最小用例可以独立于 CTest 构建（交叉编译时只链接，不运行）。
if(ASN1_BUILD_EMBEDDED_TEST AND NOT ASN1_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests/embedded)
endif()

# libFuzzer harness 可独立于单元测试构建（fuzz 专属构建不触碰 CTest 用例）。
if(ASN1_BUILD_FUZZ AND NOT ASN1_BUILD_TESTS)
  add_subdirectory(tests/fuzz)
endif()

# 差分测试辅助工具（asn1_dump），供 tests/differential/diff_asn1.py 使用。
if(ASN1_BUILD_DIFFERENTIAL)
  add_subdirectory(tests/differential)
endif()

include(Asn1Install)
asn1_install_library("${ASN1_LIBRARY_TARGETS}")
