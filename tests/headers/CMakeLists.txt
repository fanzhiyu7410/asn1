# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

# 公共头自包含编译测试：每个公共头生成一个独立翻译单元，只包含该头自身。
# 任一公共头缺少依赖包含或需要调用方先包含其他头时，构建期直接失败。

set(_asn1_header_roots "${PROJECT_SOURCE_DIR}/include")
if(TARGET asn1::pkix::static OR TARGET asn1::pkix::shared)
  list(APPEND _asn1_header_roots "${PROJECT_SOURCE_DIR}/modules/pkix/include")
endif()
if(TARGET asn1::pkcs::static OR TARGET asn1::pkcs::shared)
  list(APPEND _asn1_header_roots "${PROJECT_SOURCE_DIR}/modules/pkcs/include")
endif()
if(TARGET asn1::cms::static OR TARGET asn1::cms::shared)
  list(APPEND _asn1_header_roots "${PROJECT_SOURCE_DIR}/modules/cms/include")
endif()

set(_asn1_header_sources)
foreach(_root IN LISTS _asn1_header_roots)
  file(GLOB_RECURSE _headers CONFIGURE_DEPENDS "${_root}/asn1/*.h")
  foreach(_hdr IN LISTS _headers)
    file(RELATIVE_PATH _rel "${_root}" "${_hdr}")
    string(REPLACE "/" "_" _uid "${_rel}")
    set(ASN1_HEADER_REL "${_rel}")
    configure_file(
      "${CMAKE_CURRENT_SOURCE_DIR}/selfcontained.c.in"
      "${CMAKE_CURRENT_BINARY_DIR}/${_uid}.c"
      @ONLY
    )
    list(APPEND _asn1_header_sources "${CMAKE_CURRENT_BINARY_DIR}/${_uid}.c")
  endforeach()
endforeach()

add_library(asn1_public_headers_selfcontained OBJECT ${_asn1_header_sources})
set_target_properties(
  asn1_public_headers_selfcontained
  PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
)
if(MSVC)
  target_compile_options(asn1_public_headers_selfcontained PRIVATE /utf-8)
endif()

# 通过目标 usage requirements 获得源码树、生成头与模块头的包含路径。
if(TARGET asn1::static)
  target_link_libraries(asn1_public_headers_selfcontained PRIVATE asn1::static)
else()
  target_link_libraries(asn1_public_headers_selfcontained PRIVATE asn1::shared)
endif()
foreach(_module IN ITEMS pkix pkcs cms)
  if(TARGET asn1::${_module}::static)
    target_link_libraries(asn1_public_headers_selfcontained PRIVATE
                          asn1::${_module}::static)
  elseif(TARGET asn1::${_module}::shared)
    target_link_libraries(asn1_public_headers_selfcontained PRIVATE
                          asn1::${_module}::shared)
  endif()
endforeach()
