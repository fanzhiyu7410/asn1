# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

# asn1-pkcs：PKCS 系列标准结构模块（占位骨架）。
# 独立包与版本；只依赖核心公共 ABI，核心不反向引用本模块。
cmake_minimum_required(VERSION 3.20)

project(
  asn1-pkcs
  VERSION 0.1.0
  DESCRIPTION "PKCS 系列标准结构模块（RFC 8017/5208/2986/7292，二期占位）"
  LANGUAGES C CXX
)

set(ASN1_PKCS_SOURCES src/asn1_pkcs_version.cpp)
set(ASN1_PKCS_TARGETS "")

asn1_generate_module_version_header(pkcs)

if(ASN1_BUILD_SHARED)
  add_library(asn1_pkcs_shared SHARED ${ASN1_PKCS_SOURCES})
  set_target_properties(
    asn1_pkcs_shared
    PROPERTIES
      OUTPUT_NAME asn1-pkcs
      EXPORT_NAME shared
      VERSION ${PROJECT_VERSION}
      SOVERSION ${PROJECT_VERSION_MAJOR}
  )
  asn1_apply_module_settings(
    asn1_pkcs_shared
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${ASN1_MODULE_GENERATED_INCLUDE_DIR}"
    ASN1_PKCS_BUILDING_LIBRARY
  )
  target_link_libraries(asn1_pkcs_shared PUBLIC asn1::shared)
  add_library(asn1::pkcs::shared ALIAS asn1_pkcs_shared)
  list(APPEND ASN1_PKCS_TARGETS asn1_pkcs_shared)
endif()

if(ASN1_BUILD_STATIC)
  add_library(asn1_pkcs_static STATIC ${ASN1_PKCS_SOURCES})
  set_target_properties(
    asn1_pkcs_static
    PROPERTIES
      OUTPUT_NAME asn1-pkcs_static
      EXPORT_NAME static
  )
  asn1_apply_module_settings(
    asn1_pkcs_static
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${ASN1_MODULE_GENERATED_INCLUDE_DIR}"
    ASN1_PKCS_BUILDING_LIBRARY
  )
  target_compile_definitions(asn1_pkcs_static PRIVATE ASN1_PKCS_STATIC INTERFACE ASN1_PKCS_STATIC)
  target_link_libraries(asn1_pkcs_static PUBLIC asn1::static)
  add_library(asn1::pkcs::static ALIAS asn1_pkcs_static)
  list(APPEND ASN1_PKCS_TARGETS asn1_pkcs_static)
endif()

asn1_install_module(
  asn1-pkcs pkcs
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${ASN1_MODULE_GENERATED_INCLUDE_DIR}"
  ${ASN1_PKCS_TARGETS}
)
