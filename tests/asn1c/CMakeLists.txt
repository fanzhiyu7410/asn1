# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT
# asn1c 端到端测试：构建期用 asn1c 生成描述表，再在 C 用例中加载并校验。

set(ASN1C_PKIX_SOURCE
    ${asn1_SOURCE_DIR}/modules/pkix/asn1/PKIX-Flattened-2009.asn1)
set(ASN1C_EQUIV_SOURCE
    ${asn1_SOURCE_DIR}/tests/data/asn1c/equiv_sample.asn1)
set(ASN1C_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)

file(MAKE_DIRECTORY ${ASN1C_GENERATED_DIR})

add_custom_command(
  OUTPUT
    ${ASN1C_GENERATED_DIR}/pkix_schema.bin
    ${ASN1C_GENERATED_DIR}/pkix_schema.h
  COMMAND $<TARGET_FILE:asn1c>
    -o ${ASN1C_GENERATED_DIR}/pkix_schema.bin
    -c ${ASN1C_GENERATED_DIR}/pkix_schema.h
    --root Certificate
    ${ASN1C_PKIX_SOURCE}
  DEPENDS asn1c ${ASN1C_PKIX_SOURCE}
  COMMENT "Generating PKIX descriptor table with asn1c"
  VERBATIM
)
add_custom_target(asn1c_generated_pkix
  DEPENDS
    ${ASN1C_GENERATED_DIR}/pkix_schema.bin
    ${ASN1C_GENERATED_DIR}/pkix_schema.h
)

add_custom_command(
  OUTPUT
    ${ASN1C_GENERATED_DIR}/equiv.bin
    ${ASN1C_GENERATED_DIR}/equiv.h
  COMMAND $<TARGET_FILE:asn1c>
    -o ${ASN1C_GENERATED_DIR}/equiv.bin
    -c ${ASN1C_GENERATED_DIR}/equiv.h
    --root Container
    ${ASN1C_EQUIV_SOURCE}
  DEPENDS asn1c ${ASN1C_EQUIV_SOURCE}
  COMMENT "Generating equivalence-sample descriptor table with asn1c"
  VERBATIM
)
add_custom_target(asn1c_generated_equiv
  DEPENDS
    ${ASN1C_GENERATED_DIR}/equiv.bin
    ${ASN1C_GENERATED_DIR}/equiv.h
)

asn1_add_test(test_asn1c_pkix test_asn1c_pkix.c)
target_link_libraries(
  test_asn1c_pkix
  PRIVATE
    asn1_test_support
    asn1_test_schema_probe
    asn1_test_schema_compare
)
target_include_directories(
  test_asn1c_pkix
  PRIVATE
    ${asn1_SOURCE_DIR}/tests/data
)
target_compile_definitions(
  test_asn1c_pkix
  PRIVATE
    ASN1C_PKIX_BIN="${ASN1C_GENERATED_DIR}/pkix_schema.bin"
    ASN1C_EQUIV_BIN="${ASN1C_GENERATED_DIR}/equiv.bin"
)
add_dependencies(test_asn1c_pkix asn1c_generated_pkix asn1c_generated_equiv)

add_test(
  NAME test_asn1c_cli
  COMMAND ${CMAKE_COMMAND}
    -DASN1C_EXE=$<TARGET_FILE:asn1c>
    -DSOURCE_DIR=${asn1_SOURCE_DIR}
    -DWORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/cli
    -P ${CMAKE_CURRENT_SOURCE_DIR}/test_asn1c_cli.cmake
)
