# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

# 库目标定义。当前仅包含版本/能力查询实现，其余源文件按模块逐步加入。
# 模块目录约定：
#   core/   编解码编排、资源上限、流式适配
#   types/  ASN.1 标签与节点模型
#   ber/    BER TLV 读写与长度解析
#   der/    DER 规范化与严格校验
#   memory/ 分配器、arena 与静态池
#   error/  错误码与错误上下文
#   io/     缓冲区与 reader/writer 适配
#   schema/ 模板类型树、描述表加载与约束校验
#   c_api/  C ABI 适配层

set(ASN1_LIBRARY_SOURCES
  core/asn1_version.cpp
  core/asn1_context.cpp
  types/asn1_dom.cpp
  types/asn1_value.cpp
  ber/asn1_ber_decoder.cpp
  der/asn1_encoder.cpp
  schema/asn1_schema.cpp
  schema/asn1_schema_table.cpp
  schema/asn1_schema_decode.cpp
  schema/asn1_schema_encode.cpp
  c_api/asn1_ctx_api.cpp
  c_api/asn1_decode_api.cpp
  c_api/asn1_encode_api.cpp
  c_api/asn1_doc_api.cpp
  c_api/asn1_node_api.cpp
  c_api/asn1_schema_api.cpp
  c_api/asn1_value_basic_api.cpp
  c_api/asn1_value_text_api.cpp
)

set(ASN1_LIBRARY_TARGETS "")

if(ASN1_BUILD_SHARED)
  add_library(asn1_shared SHARED ${ASN1_LIBRARY_SOURCES})
  set_target_properties(
    asn1_shared
    PROPERTIES
      OUTPUT_NAME asn1
      EXPORT_NAME shared
      VERSION ${PROJECT_VERSION}
      SOVERSION ${PROJECT_VERSION_MAJOR}
  )
  asn1_apply_library_settings(asn1_shared)
  add_library(asn1::shared ALIAS asn1_shared)
  list(APPEND ASN1_LIBRARY_TARGETS asn1_shared)
endif()

if(ASN1_BUILD_STATIC)
  add_library(asn1_static STATIC ${ASN1_LIBRARY_SOURCES})
  set_target_properties(
    asn1_static
    PROPERTIES
      OUTPUT_NAME asn1_static
      EXPORT_NAME static
  )
  asn1_apply_library_settings(asn1_static)
  target_compile_definitions(asn1_static PRIVATE ASN1_STATIC INTERFACE ASN1_STATIC)
  add_library(asn1::static ALIAS asn1_static)
  list(APPEND ASN1_LIBRARY_TARGETS asn1_static)
endif()

set(ASN1_LIBRARY_TARGETS "${ASN1_LIBRARY_TARGETS}" PARENT_SCOPE)
