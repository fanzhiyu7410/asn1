# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

# asn1-cms：CMS/PKCS#7 标准结构模块（占位骨架）。
# 独立包与版本；只依赖核心公共 ABI，核心不反向引用本模块。
cmake_minimum_required(VERSION 3.20)

project(
  asn1-cms
  VERSION 0.1.0
  DESCRIPTION "CMS/PKCS#7 标准结构模块（RFC 6268，二期第二批，只读）"
  LANGUAGES C CXX
)

set(ASN1_CMS_SOURCES src/asn1_cms_version.cpp)
set(ASN1_CMS_TARGETS "")

asn1_generate_module_version_header(cms)

if(ASN1_BUILD_SHARED)
  add_library(asn1_cms_shared SHARED ${ASN1_CMS_SOURCES})
  set_target_properties(
    asn1_cms_shared
    PROPERTIES
      OUTPUT_NAME asn1-cms
      EXPORT_NAME shared
      VERSION ${PROJECT_VERSION}
      SOVERSION ${PROJECT_VERSION_MAJOR}
  )
  asn1_apply_module_settings(
    asn1_cms_shared
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${ASN1_MODULE_GENERATED_INCLUDE_DIR}"
    ASN1_CMS_BUILDING_LIBRARY
  )
  target_link_libraries(asn1_cms_shared PUBLIC asn1::shared)
  add_library(asn1::cms::shared ALIAS asn1_cms_shared)
  list(APPEND ASN1_CMS_TARGETS asn1_cms_shared)
endif()

if(ASN1_BUILD_STATIC)
  add_library(asn1_cms_static STATIC ${ASN1_CMS_SOURCES})
  set_target_properties(
    asn1_cms_static
    PROPERTIES
      OUTPUT_NAME asn1-cms_static
      EXPORT_NAME static
  )
  asn1_apply_module_settings(
    asn1_cms_static
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${ASN1_MODULE_GENERATED_INCLUDE_DIR}"
    ASN1_CMS_BUILDING_LIBRARY
  )
  target_compile_definitions(asn1_cms_static PRIVATE ASN1_CMS_STATIC INTERFACE ASN1_CMS_STATIC)
  target_link_libraries(asn1_cms_static PUBLIC asn1::static)
  add_library(asn1::cms::static ALIAS asn1_cms_static)
  list(APPEND ASN1_CMS_TARGETS asn1_cms_static)
endif()

asn1_install_module(
  asn1-cms cms
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${ASN1_MODULE_GENERATED_INCLUDE_DIR}"
  ${ASN1_CMS_TARGETS}
)
