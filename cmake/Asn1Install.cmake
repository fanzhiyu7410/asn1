# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

# 安装与 export：生成 asn1Config.cmake / asn1Targets.cmake，供 find_package(asn1 CONFIG) 消费。
include_guard(GLOBAL)

include(CMakePackageConfigHelpers)

function(asn1_install_library targets)
  install(
    TARGETS ${targets}
    EXPORT asn1Targets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  )

  install(
    DIRECTORY "${PROJECT_SOURCE_DIR}/include/"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    FILES_MATCHING PATTERN "*.h"
  )

  install(
    FILES "${ASN1_GENERATED_INCLUDE_DIR}/asn1/asn1_version.h"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/asn1"
  )

  set(asn1_cmake_dir "${CMAKE_INSTALL_LIBDIR}/cmake/asn1")

  install(
    EXPORT asn1Targets
    FILE asn1Targets.cmake
    NAMESPACE asn1::
    DESTINATION "${asn1_cmake_dir}"
  )

  configure_package_config_file(
    "${PROJECT_SOURCE_DIR}/cmake/asn1Config.cmake.in"
    "${PROJECT_BINARY_DIR}/asn1Config.cmake"
    INSTALL_DESTINATION "${asn1_cmake_dir}"
  )

  write_basic_package_version_file(
    "${PROJECT_BINARY_DIR}/asn1ConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
  )

  install(
    FILES
      "${PROJECT_BINARY_DIR}/asn1Config.cmake"
      "${PROJECT_BINARY_DIR}/asn1ConfigVersion.cmake"
    DESTINATION "${asn1_cmake_dir}"
  )
endfunction()
