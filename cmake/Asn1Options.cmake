# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

# 构建选项定义。
# 所有选项均以缓存变量暴露，便于上层项目或交叉编译工具链覆盖。
include_guard(GLOBAL)

option(ASN1_BUILD_SHARED "构建共享库目标 asn1::shared" ON)
option(ASN1_BUILD_STATIC "构建静态库目标 asn1::static" ON)
option(ASN1_BUILD_MODULES "构建 modules/ 下的独立标准模块" ON)
option(ASN1_BUILD_MODULE_PKIX "构建 asn1-pkix 模块（仅 ASN1_BUILD_MODULES=ON 时生效）" ON)
option(ASN1_BUILD_MODULE_CMS "构建 asn1-cms 模块（仅 ASN1_BUILD_MODULES=ON 时生效）" ON)
option(ASN1_BUILD_MODULE_PKCS "构建 asn1-pkcs 模块（仅 ASN1_BUILD_MODULES=ON 时生效）" ON)
option(ASN1_BUILD_TOOLS "构建 tools/asn1c" ON)
option(
  ASN1_PKIX_REGENERATE_TABLE
  "构建期用 asn1c 重新生成 asn1-pkix 描述表，并与检入产物逐字节比对（默认使用检入产物）"
  OFF
)
option(ASN1_BUILD_EXAMPLES "构建 C 与 C++ 消费示例" OFF)
option(ASN1_BUILD_BENCHMARKS "构建可选基准（不进 CTest 主流程）" OFF)
option(ASN1_BUILD_TESTS "构建单元测试并注册到 CTest" OFF)
option(
  ASN1_BUILD_FUZZ
  "构建 libFuzzer harness（tests/fuzz，需 Clang；覆盖率/ASan/UBSan 由全局 flags 注入）"
  OFF
)
option(
  ASN1_BUILD_DIFFERENTIAL
  "构建差分测试辅助工具 asn1_dump（tests/differential）"
  OFF
)
option(
  ASN1_BUILD_EMBEDDED_TEST
  "构建嵌入式最小用例 tests/embedded（静态池、无堆、无标准 IO），可独立于 CTest 交叉编译"
  OFF
)
option(ASN1_FREESTANDING "按 freestanding 子集构建（无异常、无 RTTI、无标准 IO）" OFF)
option(ASN1_WARNINGS_AS_ERRORS "将编译警告视为错误" OFF)
option(ASN1_ENABLE_SANITIZERS "启用 AddressSanitizer 与 UBSan（仅宿主平台调试构建）" OFF)

set(ASN1_CXX_STANDARD "17" CACHE STRING "内部 C++ 实现使用的语言标准（基线为 17）")
set_property(CACHE ASN1_CXX_STANDARD PROPERTY STRINGS 17 20)

if(NOT ASN1_BUILD_SHARED AND NOT ASN1_BUILD_STATIC)
  message(FATAL_ERROR "至少需要启用一个库目标：ASN1_BUILD_SHARED 或 ASN1_BUILD_STATIC")
endif()

if(ASN1_CXX_STANDARD STREQUAL "14")
  message(FATAL_ERROR "基线要求 C++17 或更高；14 仅作为历史记录保留在文档中，不受支持")
endif()

if(ASN1_BUILD_SHARED)
  set(ASN1_HAS_SHARED_TARGET ON)
endif()
