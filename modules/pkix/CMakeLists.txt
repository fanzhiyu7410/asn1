# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

# asn1-pkix：X.509/PKIX 标准结构模块。
# 独立包与版本；只依赖核心公共 ABI，核心不反向引用本模块。
cmake_minimum_required(VERSION 3.20)

project(
  asn1-pkix
  VERSION 0.1.1
  DESCRIPTION "X.509/PKIX 标准结构模块（RFC 5912）"
  LANGUAGES C CXX
)

set(ASN1_PKIX_SOURCES
  src/asn1_pkix_certificate.cpp
  src/asn1_pkix_version.cpp
)
set(ASN1_PKIX_TARGETS "")

# 描述表产物：检入 modules/pkix/generated/，未安装、不进入公共头。
set(ASN1_PKIX_CHECKED_IN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/generated")
set(ASN1_PKIX_CHECKED_IN_BIN "${ASN1_PKIX_CHECKED_IN_DIR}/pkix_schema.bin")
set(ASN1_PKIX_CHECKED_IN_HEADER "${ASN1_PKIX_CHECKED_IN_DIR}/pkix_schema.h")
set(ASN1_PKIX_ASN1 "${CMAKE_CURRENT_SOURCE_DIR}/asn1/PKIX-Flattened-2009.asn1")

if(ASN1_PKIX_REGENERATE_TABLE)
  if(NOT TARGET asn1c)
    message(
      FATAL_ERROR
      "ASN1_PKIX_REGENERATE_TABLE=ON 需要同时启用 ASN1_BUILD_TOOLS=ON 以提供 asn1c"
    )
  endif()
  set(regenerated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated/table")
  file(MAKE_DIRECTORY "${regenerated_dir}")
  set(regenerated_bin "${regenerated_dir}/pkix_schema.bin")
  set(regenerated_header "${regenerated_dir}/pkix_schema.h")

  add_custom_command(
    OUTPUT "${regenerated_bin}" "${regenerated_header}"
    COMMAND
      $<TARGET_FILE:asn1c> -o "${regenerated_bin}" -c "${regenerated_header}"
      --root Certificate "${ASN1_PKIX_ASN1}"
    DEPENDS asn1c "${ASN1_PKIX_ASN1}"
    COMMENT "用 asn1c 重新生成 asn1-pkix 描述表"
    VERBATIM
  )
  add_custom_target(asn1_pkix_table_generate
    DEPENDS "${regenerated_bin}" "${regenerated_header}"
  )

  # 与检入产物逐字节比对；任一差异或缺失即构建失败，避免长期漂移。
  add_custom_target(asn1_pkix_table_verify
    COMMAND
      ${CMAKE_COMMAND} -E compare_files "${regenerated_bin}" "${ASN1_PKIX_CHECKED_IN_BIN}"
    COMMAND
      ${CMAKE_COMMAND} -E compare_files "${regenerated_header}" "${ASN1_PKIX_CHECKED_IN_HEADER}"
    DEPENDS asn1_pkix_table_generate "${ASN1_PKIX_CHECKED_IN_BIN}"
            "${ASN1_PKIX_CHECKED_IN_HEADER}"
    COMMENT "校验重新生成的描述表与检入产物逐字节一致"
    VERBATIM
  )
  set(pkix_table_include_dir "${regenerated_dir}")
  set(pkix_table_header "${regenerated_header}")
else()
  if(NOT EXISTS "${ASN1_PKIX_CHECKED_IN_BIN}" OR
     NOT EXISTS "${ASN1_PKIX_CHECKED_IN_HEADER}")
    message(FATAL_ERROR "缺少检入的 asn1-pkix 描述表产物：${ASN1_PKIX_CHECKED_IN_DIR}")
  endif()
  set(pkix_table_include_dir "${ASN1_PKIX_CHECKED_IN_DIR}")
  set(pkix_table_header "${ASN1_PKIX_CHECKED_IN_HEADER}")
endif()

asn1_generate_module_version_header(pkix)

if(ASN1_BUILD_SHARED)
  add_library(asn1_pkix_shared SHARED ${ASN1_PKIX_SOURCES})
  set_target_properties(
    asn1_pkix_shared
    PROPERTIES
      OUTPUT_NAME asn1-pkix
      EXPORT_NAME shared
      VERSION ${PROJECT_VERSION}
      SOVERSION ${PROJECT_VERSION_MAJOR}
  )
  asn1_apply_module_settings(
    asn1_pkix_shared
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${ASN1_MODULE_GENERATED_INCLUDE_DIR}"
    ASN1_PKIX_BUILDING_LIBRARY
  )
  target_include_directories(asn1_pkix_shared PRIVATE "${pkix_table_include_dir}")
  target_sources(asn1_pkix_shared PRIVATE "${pkix_table_header}")
  target_link_libraries(asn1_pkix_shared PUBLIC asn1::shared)
  add_library(asn1::pkix::shared ALIAS asn1_pkix_shared)
  list(APPEND ASN1_PKIX_TARGETS asn1_pkix_shared)
endif()

if(ASN1_BUILD_STATIC)
  add_library(asn1_pkix_static STATIC ${ASN1_PKIX_SOURCES})
  set_target_properties(
    asn1_pkix_static
    PROPERTIES
      OUTPUT_NAME asn1-pkix_static
      EXPORT_NAME static
  )
  asn1_apply_module_settings(
    asn1_pkix_static
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${ASN1_MODULE_GENERATED_INCLUDE_DIR}"
    ASN1_PKIX_BUILDING_LIBRARY
  )
  target_include_directories(asn1_pkix_static PRIVATE "${pkix_table_include_dir}")
  target_sources(asn1_pkix_static PRIVATE "${pkix_table_header}")
  target_compile_definitions(asn1_pkix_static PRIVATE ASN1_PKIX_STATIC INTERFACE ASN1_PKIX_STATIC)
  target_link_libraries(asn1_pkix_static PUBLIC asn1::static)
  add_library(asn1::pkix::static ALIAS asn1_pkix_static)
  list(APPEND ASN1_PKIX_TARGETS asn1_pkix_static)
endif()

if(ASN1_PKIX_REGENERATE_TABLE)
  if(TARGET asn1_pkix_shared)
    add_dependencies(asn1_pkix_shared asn1_pkix_table_verify)
  endif()
  if(TARGET asn1_pkix_static)
    add_dependencies(asn1_pkix_static asn1_pkix_table_verify)
  endif()
endif()

asn1_install_module(
  asn1-pkix pkix
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${ASN1_MODULE_GENERATED_INCLUDE_DIR}"
  ${ASN1_PKIX_TARGETS}
)
