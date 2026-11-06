# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

# 标准模块的构建与安装辅助。
# 模块只依赖核心公共 ABI；每个模块拥有独立包名、版本、导出集与头文件目录。
include_guard(GLOBAL)

include(CMakePackageConfigHelpers)

function(asn1_apply_module_settings target module_dir generated_dir define_name)
  set(generated_include_dirs)
  if(generated_dir)
    list(APPEND generated_include_dirs
      $<BUILD_INTERFACE:${generated_dir}>)
  endif()

  target_include_directories(
    ${target}
    PUBLIC
      $<BUILD_INTERFACE:${module_dir}/include>
      ${generated_include_dirs}
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
      ${module_dir}/src
  )

  target_compile_definitions(${target} PRIVATE ${define_name})

  asn1_apply_common_settings(${target})
endfunction()

# package：包名，如 asn1-pkix
# name：命名空间片段，如 pkix
# module_dir：模块根目录
# generated_dir：模块版本头生成目录
# 其余参数：需要安装的模块目标
function(asn1_install_module package name module_dir generated_dir)
  set(module_targets ${ARGN})
  if(NOT module_targets)
    return()
  endif()

  install(
    TARGETS ${module_targets}
    EXPORT ${package}Targets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  )

  install(
    DIRECTORY "${module_dir}/include/"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    FILES_MATCHING PATTERN "*.h"
  )

  install(
    FILES "${generated_dir}/asn1/${name}/${name}_version.h"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/asn1/${name}"
  )

  set(module_cmake_dir "${CMAKE_INSTALL_LIBDIR}/cmake/${package}")

  install(
    EXPORT ${package}Targets
    FILE ${package}Targets.cmake
    NAMESPACE asn1::${name}::
    DESTINATION "${module_cmake_dir}"
  )

  set(ASN1_MODULE_PACKAGE "${package}")
  set(ASN1_CORE_VERSION "${asn1_VERSION}")

  configure_package_config_file(
    "${asn1_SOURCE_DIR}/cmake/asn1ModuleConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/${package}Config.cmake"
    INSTALL_DESTINATION "${module_cmake_dir}"
  )

  write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/${package}ConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
  )

  install(
    FILES
      "${CMAKE_CURRENT_BINARY_DIR}/${package}Config.cmake"
      "${CMAKE_CURRENT_BINARY_DIR}/${package}ConfigVersion.cmake"
    DESTINATION "${module_cmake_dir}"
  )
endfunction()
