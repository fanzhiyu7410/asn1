# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

# asn1-pkcs：PKCS 系列标准结构模块（只读结构访问）。
# 独立包与版本；只依赖核心公共 ABI，核心不反向引用本模块。
cmake_minimum_required(VERSION 3.20)

project(
  asn1-pkcs
  VERSION 0.1.1
  DESCRIPTION "PKCS 系列标准结构模块（RFC 8017/5208/2986/7292，只读）"
  LANGUAGES C CXX
)

set(ASN1_PKCS_SOURCES
  src/asn1_pkcs_structures.cpp
  src/asn1_pkcs12_structures.cpp
  src/asn1_pkcs_version.cpp
  src/pkcs_handle.cpp
  src/pkcs8_private_key_info_table.cpp
  src/pkcs8_encrypted_private_key_info_table.cpp
  src/pkcs1_rsa_public_key_table.cpp
  src/pkcs1_rsa_private_key_table.cpp
  src/pkcs10_certification_request_table.cpp
  src/pkcs10_certification_request_info_table.cpp
  src/pkcs12_pfx_table.cpp
  src/pkcs12_authenticated_safe_table.cpp
  src/pkcs12_safe_contents_table.cpp
  src/pkcs12_cert_bag_table.cpp
)
set(ASN1_PKCS_TARGETS "")

# 描述表产物：检入 modules/pkcs/generated/，未安装、不进入公共头。
# PKCS#8 + PKCS#1 + PKCS#10 + PKCS#12 共 10 个顶层结构，asn1c 每张表只接受
# 一个 --root，因此生成 10 张表。
set(ASN1_PKCS_CHECKED_IN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/generated")
set(ASN1_PKCS_ASN1_5208 "${CMAKE_CURRENT_SOURCE_DIR}/asn1/PKCS8-Flattened-5208.asn1")
set(ASN1_PKCS_ASN1_8017 "${CMAKE_CURRENT_SOURCE_DIR}/asn1/PKCS1-Flattened-8017.asn1")
set(ASN1_PKCS_ASN1_2986 "${CMAKE_CURRENT_SOURCE_DIR}/asn1/PKCS10-Flattened-2986.asn1")
set(ASN1_PKCS_ASN1_7292 "${CMAKE_CURRENT_SOURCE_DIR}/asn1/PKCS12-Flattened-7292.asn1")

set(ASN1_PKCS_TABLE_NAMES
  pkcs8_private_key_info_schema
  pkcs8_encrypted_private_key_info_schema
  pkcs1_rsa_public_key_schema
  pkcs1_rsa_private_key_schema
  pkcs10_certification_request_schema
  pkcs10_certification_request_info_schema
  pkcs12_pfx_schema
  pkcs12_authenticated_safe_schema
  pkcs12_safe_contents_schema
  pkcs12_cert_bag_schema
)
set(ASN1_PKCS_TABLE_ROOTS
  PrivateKeyInfo
  EncryptedPrivateKeyInfo
  RSAPublicKey
  RSAPrivateKey
  CertificationRequest
  CertificationRequestInfo
  PFX
  AuthenticatedSafe
  SafeContents
  CertBag
)
set(ASN1_PKCS_TABLE_INPUTS
  "${ASN1_PKCS_ASN1_5208}"
  "${ASN1_PKCS_ASN1_5208}"
  "${ASN1_PKCS_ASN1_8017}"
  "${ASN1_PKCS_ASN1_8017}"
  "${ASN1_PKCS_ASN1_2986}"
  "${ASN1_PKCS_ASN1_2986}"
  "${ASN1_PKCS_ASN1_7292}"
  "${ASN1_PKCS_ASN1_7292}"
  "${ASN1_PKCS_ASN1_7292}"
  "${ASN1_PKCS_ASN1_7292}"
)

set(ASN1_PKCS_CHECKED_IN_BINARIES "")
set(ASN1_PKCS_CHECKED_IN_HEADERS "")
foreach(name IN LISTS ASN1_PKCS_TABLE_NAMES)
  list(APPEND ASN1_PKCS_CHECKED_IN_BINARIES "${ASN1_PKCS_CHECKED_IN_DIR}/${name}.bin")
  list(APPEND ASN1_PKCS_CHECKED_IN_HEADERS "${ASN1_PKCS_CHECKED_IN_DIR}/${name}.h")
endforeach()

if(ASN1_PKCS_REGENERATE_TABLE)
  if(NOT TARGET asn1c)
    message(
      FATAL_ERROR
      "ASN1_PKCS_REGENERATE_TABLE=ON 需要同时启用 ASN1_BUILD_TOOLS=ON 以提供 asn1c"
    )
  endif()
  set(pkcs_regenerated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated/table")
  file(MAKE_DIRECTORY "${pkcs_regenerated_dir}")
  set(pkcs_regenerated_outputs "")

  foreach(name root input IN ZIP_LISTS ASN1_PKCS_TABLE_NAMES ASN1_PKCS_TABLE_ROOTS ASN1_PKCS_TABLE_INPUTS)
    set(regenerated_bin "${pkcs_regenerated_dir}/${name}.bin")
    set(regenerated_header "${pkcs_regenerated_dir}/${name}.h")
    add_custom_command(
      OUTPUT "${regenerated_bin}" "${regenerated_header}"
      COMMAND
        $<TARGET_FILE:asn1c> -o "${regenerated_bin}" -c "${regenerated_header}"
        --root "${root}" "${input}"
      DEPENDS asn1c "${input}"
      COMMENT "用 asn1c 重新生成 asn1-pkcs 描述表 ${name}（根 ${root}）"
      VERBATIM
    )
    list(APPEND pkcs_regenerated_outputs "${regenerated_bin}" "${regenerated_header}")
  endforeach()

  add_custom_target(asn1_pkcs_table_generate DEPENDS ${pkcs_regenerated_outputs})

  # 与检入产物逐字节比对；任一差异或缺失即构建失败，避免长期漂移。
  set(pkcs_verify_commands "")
  foreach(name IN LISTS ASN1_PKCS_TABLE_NAMES)
    list(APPEND pkcs_verify_commands
      COMMAND
        ${CMAKE_COMMAND} -E compare_files
        "${pkcs_regenerated_dir}/${name}.bin"
        "${ASN1_PKCS_CHECKED_IN_DIR}/${name}.bin"
      COMMAND
        ${CMAKE_COMMAND} -E compare_files
        "${pkcs_regenerated_dir}/${name}.h"
        "${ASN1_PKCS_CHECKED_IN_DIR}/${name}.h"
    )
  endforeach()
  add_custom_target(asn1_pkcs_table_verify
    ${pkcs_verify_commands}
    DEPENDS asn1_pkcs_table_generate ${ASN1_PKCS_CHECKED_IN_BINARIES}
            ${ASN1_PKCS_CHECKED_IN_HEADERS}
    COMMENT "校验重新生成的 asn1-pkcs 描述表与检入产物逐字节一致"
    VERBATIM
  )
  set(pkcs_table_include_dir "${pkcs_regenerated_dir}")
else()
  foreach(path IN LISTS ASN1_PKCS_CHECKED_IN_BINARIES ASN1_PKCS_CHECKED_IN_HEADERS)
    if(NOT EXISTS "${path}")
      message(FATAL_ERROR "缺少检入的 asn1-pkcs 描述表产物：${path}")
    endif()
  endforeach()
  set(pkcs_table_include_dir "${ASN1_PKCS_CHECKED_IN_DIR}")
endif()

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
  target_include_directories(asn1_pkcs_shared PRIVATE "${pkcs_table_include_dir}")
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
  target_include_directories(asn1_pkcs_static PRIVATE "${pkcs_table_include_dir}")
  target_compile_definitions(asn1_pkcs_static PRIVATE ASN1_PKCS_STATIC INTERFACE ASN1_PKCS_STATIC)
  target_link_libraries(asn1_pkcs_static PUBLIC asn1::static)
  add_library(asn1::pkcs::static ALIAS asn1_pkcs_static)
  list(APPEND ASN1_PKCS_TARGETS asn1_pkcs_static)
endif()

if(ASN1_PKCS_REGENERATE_TABLE)
  if(TARGET asn1_pkcs_shared)
    add_dependencies(asn1_pkcs_shared asn1_pkcs_table_verify)
  endif()
  if(TARGET asn1_pkcs_static)
    add_dependencies(asn1_pkcs_static asn1_pkcs_table_verify)
  endif()
endif()

asn1_install_module(
  asn1-pkcs pkcs
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${ASN1_MODULE_GENERATED_INCLUDE_DIR}"
  ${ASN1_PKCS_TARGETS}
)
