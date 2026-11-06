# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

add_library(asn1_test_support INTERFACE)
target_include_directories(asn1_test_support INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

# 测试专用 schema 探针：读取内部类型树并投影为 C 可见结构。
# 只服务测试，不进入公共头或核心库。
add_library(asn1_test_schema_probe STATIC schema_probe.cpp)
target_link_libraries(asn1_test_schema_probe PUBLIC asn1_test_support)
target_include_directories(
  asn1_test_schema_probe
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src
    ${ASN1_GENERATED_INCLUDE_DIR}
)
set_target_properties(
  asn1_test_schema_probe
  PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)
if(MSVC)
  target_compile_options(asn1_test_schema_probe PRIVATE /utf-8)
endif()

asn1_add_test(test_support test_support.c)
target_link_libraries(test_support PRIVATE asn1_test_support)

# 测试专用 schema 等价比较：逐类型/字段/约束比较两条已封存类型树。
add_library(asn1_test_schema_compare STATIC schema_compare.c)
target_link_libraries(asn1_test_schema_compare PUBLIC asn1_test_schema_probe)
target_include_directories(
  asn1_test_schema_compare
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${ASN1_GENERATED_INCLUDE_DIR}
)
