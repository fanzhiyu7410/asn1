# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

# asn1-cms：CMS/PKCS#7 标准结构模块（RFC 5652 只读结构访问）。
# 独立包与版本；只依赖核心公共 ABI，核心不反向引用本模块。
cmake_minimum_required(VERSION 3.20)

project(
  asn1-cms
  VERSION 0.1.1
  DESCRIPTION "CMS/PKCS#7 标准结构模块（RFC 5652，只读）"
  LANGUAGES C CXX
)

set(ASN1_CMS_SOURCES
  src/asn1_cms_builder.cpp
  src/asn1_cms_structures.cpp
  src/asn1_cms_version.cpp
  src/cms_content_info_table.cpp
  src/cms_signed_data_table.cpp
)
set(ASN1_CMS_TARGETS "")

# 描述表产物：检入 modules/cms/generated/，未安装、不进入公共头。
# 本轮只读切片覆盖 ContentInfo 与 SignedData 两个顶层结构，各生成一张表。
set(ASN1_CMS_CHECKED_IN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/generated")
set(ASN1_CMS_ASN1_5652 "${CMAKE_CURRENT_SOURCE_DIR}/asn1/CMS-Flattened-5652.asn1")

set(ASN1_CMS_TABLE_NAMES
  cms_content_info_schema
  cms_signed_data_schema
)
set(ASN1_CMS_TABLE_ROOTS
  ContentInfo
  SignedData
)
set(ASN1_CMS_TABLE_INPUTS
  "${ASN1_CMS_ASN1_5652}"
  "${ASN1_CMS_ASN1_5652}"
)

set(ASN1_CMS_CHECKED_IN_BINARIES "")
set(ASN1_CMS_CHECKED_IN_HEADERS "")
foreach(name IN LISTS ASN1_CMS_TABLE_NAMES)
  list(APPEND ASN1_CMS_CHECKED_IN_BINARIES "${ASN1_CMS_CHECKED_IN_DIR}/${name}.bin")
  list(APPEND ASN1_CMS_CHECKED_IN_HEADERS "${ASN1_CMS_CHECKED_IN_DIR}/${name}.h")
endforeach()

if(ASN1_CMS_REGENERATE_TABLE)
  if(NOT TARGET asn1c)
    message(
      FATAL_ERROR
      "ASN1_CMS_REGENERATE_TABLE=ON 需要同时启用 ASN1_BUILD_TOOLS=ON 以提供 asn1c"
    )
  endif()
  set(cms_regenerated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated/table")
  file(MAKE_DIRECTORY "${cms_regenerated_dir}")
  set(cms_regenerated_outputs "")

  foreach(name root input IN ZIP_LISTS ASN1_CMS_TABLE_NAMES ASN1_CMS_TABLE_ROOTS ASN1_CMS_TABLE_INPUTS)
    set(regenerated_bin "${cms_regenerated_dir}/${name}.bin")
    set(regenerated_header "${cms_regenerated_dir}/${name}.h")
    add_custom_command(
      OUTPUT "${regenerated_bin}" "${regenerated_header}"
      COMMAND
        $<TARGET_FILE:asn1c> -o "${regenerated_bin}" -c "${regenerated_header}"
        --root "${root}" "${input}"
      DEPENDS asn1c "${input}"
      COMMENT "用 asn1c 重新生成 asn1-cms 描述表 ${name}（根 ${root}）"
      VERBATIM
    )
    list(APPEND cms_regenerated_outputs "${regenerated_bin}" "${regenerated_header}")
  endforeach()

  add_custom_target(asn1_cms_table_generate DEPENDS ${cms_regenerated_outputs})

  # 与检入产物逐字节比对；任一差异或缺失即构建失败，避免长期漂移。
  set(cms_verify_commands "")
  foreach(name IN LISTS ASN1_CMS_TABLE_NAMES)
    list(APPEND cms_verify_commands
      COMMAND
        ${CMAKE_COMMAND} -E compare_files
        "${cms_regenerated_dir}/${name}.bin"
        "${ASN1_CMS_CHECKED_IN_DIR}/${name}.bin"
      COMMAND
        ${CMAKE_COMMAND} -E compare_files
        "${cms_regenerated_dir}/${name}.h"
        "${ASN1_CMS_CHECKED_IN_DIR}/${name}.h"
    )
  endforeach()
  add_custom_target(asn1_cms_table_verify
    ${cms_verify_commands}
    DEPENDS asn1_cms_table_generate ${ASN1_CMS_CHECKED_IN_BINARIES}
            ${ASN1_CMS_CHECKED_IN_HEADERS}
    COMMENT "校验重新生成的 asn1-cms 描述表与检入产物逐字节一致"
    VERBATIM
  )
  set(cms_table_include_dir "${cms_regenerated_dir}")
else()
  foreach(path IN LISTS ASN1_CMS_CHECKED_IN_BINARIES ASN1_CMS_CHECKED_IN_HEADERS)
    if(NOT EXISTS "${path}")
      message(FATAL_ERROR "缺少检入的 asn1-cms 描述表产物：${path}")
    endif()
  endforeach()
  set(cms_table_include_dir "${ASN1_CMS_CHECKED_IN_DIR}")
endif()

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
  target_include_directories(asn1_cms_shared PRIVATE "${cms_table_include_dir}")
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
  target_include_directories(asn1_cms_static PRIVATE "${cms_table_include_dir}")
  target_compile_definitions(asn1_cms_static PRIVATE ASN1_CMS_STATIC INTERFACE ASN1_CMS_STATIC)
  target_link_libraries(asn1_cms_static PUBLIC asn1::static)
  add_library(asn1::cms::static ALIAS asn1_cms_static)
  list(APPEND ASN1_CMS_TARGETS asn1_cms_static)
endif()

if(ASN1_CMS_REGENERATE_TABLE)
  if(TARGET asn1_cms_shared)
    add_dependencies(asn1_cms_shared asn1_cms_table_verify)
  endif()
  if(TARGET asn1_cms_static)
    add_dependencies(asn1_cms_static asn1_cms_table_verify)
  endif()
endif()

asn1_install_module(
  asn1-cms cms
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${ASN1_MODULE_GENERATED_INCLUDE_DIR}"
  ${ASN1_CMS_TARGETS}
)
