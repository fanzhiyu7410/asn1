# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

# 版本头生成。
# 唯一真源是各包自己的 project(... VERSION ...)；源码树中不手写版本宏。
include_guard(GLOBAL)

# 配置期断言：生成头的 MAJOR/MINOR/PATCH/STRING 逐项与 project VERSION 比对。
# prefix 为宏前缀，核心传 ASN1，模块传 ASN1_<模块大写>，工具传 ASN1C。
function(asn1_assert_generated_version_header header expected_major expected_minor
         expected_patch expected_string prefix)
  if(NOT EXISTS "${header}")
    message(FATAL_ERROR "版本头未生成：${header}")
  endif()

  file(READ "${header}" _asn1_version_header_content)

  foreach(_asn1_part MAJOR MINOR PATCH)
    string(REGEX MATCH "#define ${prefix}_VERSION_${_asn1_part} ([0-9]+)"
           _asn1_version_match "${_asn1_version_header_content}")
    if(NOT _asn1_version_match)
      message(FATAL_ERROR
        "版本头 ${header} 缺少宏 ${prefix}_VERSION_${_asn1_part}")
    endif()
    string(TOLOWER "${_asn1_part}" _asn1_part_lower)
    set(_asn1_expected_value "${expected_${_asn1_part_lower}}")
    if(NOT "${CMAKE_MATCH_1}" STREQUAL "${_asn1_expected_value}")
      message(FATAL_ERROR
        "版本头 ${header} 的 ${prefix}_VERSION_${_asn1_part}=${CMAKE_MATCH_1} "
        "与 project VERSION 的 ${_asn1_part}=${_asn1_expected_value} 不一致")
    endif()
  endforeach()

  string(REGEX MATCH "#define ${prefix}_VERSION_STRING \"([^\"]*)\""
         _asn1_version_string_match "${_asn1_version_header_content}")
  if(NOT _asn1_version_string_match)
    message(FATAL_ERROR
      "版本头 ${header} 缺少宏 ${prefix}_VERSION_STRING")
  endif()
  if(NOT "${CMAKE_MATCH_1}" STREQUAL "${expected_string}")
    message(FATAL_ERROR
      "版本头 ${header} 的 ${prefix}_VERSION_STRING=${CMAKE_MATCH_1} "
      "与 project VERSION ${expected_string} 不一致")
  endif()
endfunction()

# 核心版本头：构建目录 generated/include/asn1/asn1_version.h。
# 结果通过 ASN1_GENERATED_INCLUDE_DIR 暴露给上层，并在安装阶段复制到 include/asn1/。
function(asn1_generate_core_version_header)
  set(generated_dir "${CMAKE_BINARY_DIR}/generated/include")
  file(MAKE_DIRECTORY "${generated_dir}/asn1")

  configure_file(
    "${asn1_SOURCE_DIR}/cmake/asn1_version.h.in"
    "${generated_dir}/asn1/asn1_version.h"
    @ONLY
  )

  asn1_assert_generated_version_header(
    "${generated_dir}/asn1/asn1_version.h"
    "${PROJECT_VERSION_MAJOR}" "${PROJECT_VERSION_MINOR}"
    "${PROJECT_VERSION_PATCH}" "${PROJECT_VERSION}" "ASN1")

  set(ASN1_GENERATED_INCLUDE_DIR "${generated_dir}" PARENT_SCOPE)
endfunction()

# 模块版本头：<module_binary_dir>/generated/include/asn1/<name>/<name>_version.h。
# 结果通过 ASN1_MODULE_GENERATED_INCLUDE_DIR 暴露给调用方的目录作用域。
function(asn1_generate_module_version_header name)
  string(TOUPPER "${name}" module_upper)
  set(ASN1_MODULE_MACRO "ASN1_${module_upper}")

  set(generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated/include")
  file(MAKE_DIRECTORY "${generated_dir}/asn1/${name}")

  configure_file(
    "${asn1_SOURCE_DIR}/cmake/asn1ModuleVersion.h.in"
    "${generated_dir}/asn1/${name}/${name}_version.h"
    @ONLY
  )

  asn1_assert_generated_version_header(
    "${generated_dir}/asn1/${name}/${name}_version.h"
    "${PROJECT_VERSION_MAJOR}" "${PROJECT_VERSION_MINOR}"
    "${PROJECT_VERSION_PATCH}" "${PROJECT_VERSION}" "${ASN1_MODULE_MACRO}")

  set(ASN1_MODULE_GENERATED_INCLUDE_DIR "${generated_dir}" PARENT_SCOPE)
endfunction()
