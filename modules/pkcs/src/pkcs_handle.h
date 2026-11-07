/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asn1-pkcs 模块内共享的句柄与字段访问工具（私有）。
 *
 * 多个结构切片（PKCS#1/#8/#10 与 PKCS#12）共用同一套“加载 schema → DER
 * 严格解码 → 持有文档”的句柄骨架，以及字段/ANY/属性读取辅助函数。这些
 * 符号不导出，只供模块自身编译单元使用。
 */

#ifndef ASN1_PKCS_HANDLE_H_INCLUDED
#define ASN1_PKCS_HANDLE_H_INCLUDED

#include <asn1/asn1_build.h>
#include <asn1/asn1_node.h>
#include <asn1/asn1_schema.h>

#include "pkcs_tables.h"

#include <cstdlib>

namespace pkcs_internal {

constexpr uint32_t kPkcsFormatVersion = 1u << 16;

/* 所有结构句柄共享的字段；派生句柄以它为第一个成员。 */
struct handle_base {
    asn1_ctx_t *ctx;
    asn1_schema_t *schema;
    asn1_doc_t *doc;
    const asn1_node_t *root;
};

template <typename T>
asn1_err_t openStructure(asn1_ctx_t *ctx, const uint8_t *der, size_t der_size,
                         pkcs_table_view table, T **out_object) noexcept
{
    if (ctx == nullptr || der == nullptr || der_size == 0 ||
        out_object == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    *out_object = nullptr;

    asn1_schema_table_t schema_table;
    schema_table.struct_size = sizeof(schema_table);
    schema_table.data = table.data;
    schema_table.size = table.size;
    schema_table.format_version = kPkcsFormatVersion;
    schema_table.reserved = 0;

    asn1_schema_t *schema = nullptr;
    asn1_err_t status = asn1_schema_load(ctx, &schema_table, &schema);
    if (status != ASN1_OK) {
        return status;
    }

    asn1_decode_options_t options;
    asn1_decode_options_init(&options);
    options.encoding = ASN1_ENCODING_DER;
    options.flags = ASN1_DECODE_COPY_INPUT;

    asn1_doc_t *doc = nullptr;
    size_t consumed = 0;
    status = asn1_decode_buffer_with_schema(ctx, der, der_size, schema,
                                            &options, &doc, &consumed);
    if (status != ASN1_OK) {
        asn1_schema_destroy(schema);
        return status;
    }

    T *object = static_cast<T *>(std::malloc(sizeof(T)));
    if (object == nullptr) {
        asn1_doc_destroy(doc);
        asn1_schema_destroy(schema);
        return ASN1_E_NOMEM;
    }

    object->ctx = ctx;
    object->schema = schema;
    object->doc = doc;
    object->root = asn1_doc_root(doc);
    *out_object = object;
    return ASN1_OK;
}

void closeStructure(handle_base *object) noexcept;

/* 取顶层字段；字段缺省时返回 nullptr。 */
const asn1_node_t *field(const handle_base *object,
                         const char *name) noexcept;

/* 取两个层级，例如 privateKeyAlgorithm.algorithm。 */
const asn1_node_t *nestedField(const handle_base *object,
                               const char *container,
                               const char *name) noexcept;

asn1_err_t requireField(const handle_base *object, const char *name,
                        const asn1_node_t **out_node) noexcept;

asn1_err_t algorithmOid(const handle_base *object, const char *container,
                        const char **out_dotted, size_t *out_size) noexcept;

/* ANY 参数：完整原始 TLV；字段缺省时 ASN1_OK + NULL/0。 */
asn1_err_t algorithmParameters(const handle_base *object,
                               const char *container,
                               const uint8_t **out_data,
                               size_t *out_size) noexcept;

asn1_err_t bigintField(const handle_base *object, const char *name,
                       const char **out_decimal, size_t *out_size) noexcept;

asn1_err_t octetsField(const handle_base *object, const char *name,
                       const uint8_t **out_data, size_t *out_size) noexcept;

asn1_err_t tlvField(const handle_base *object, const char *name,
                    const uint8_t **out_data, size_t *out_size) noexcept;

} // namespace pkcs_internal

#endif /* ASN1_PKCS_HANDLE_H_INCLUDED */
