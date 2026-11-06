/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 只读节点访问与语义读取。契约见 docs/02-C-API规范.md 第 6 节与 6.6。
 * 所有指针均为文档借用，生命周期不超过所属文档。
 */
#ifndef ASN1_ASN1_NODE_H_INCLUDED
#define ASN1_ASN1_NODE_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include <asn1/asn1_decode.h>
#include <asn1/asn1_error.h>
#include <asn1/asn1_export.h>

/* 节点在源编码中实际使用的形式（与 schema 的 kind 无关）。 */
typedef enum asn1_encoding_form {
    ASN1_FORM_PRIMITIVE = 0,    /* 基本形式 */
    ASN1_FORM_CONSTRUCTED = 1   /* 构造形式（含 BER 构造字符串） */
} asn1_encoding_form_t;

/* ASN1_TIME_* 位标志，语义见 docs/02-C-API规范.md 5.3。 */
#define ASN1_TIME_UTC ((uint32_t)(1u << 0))
#define ASN1_TIME_GENERALIZED ((uint32_t)(1u << 1))
#define ASN1_TIME_HAS_OFFSET ((uint32_t)(1u << 2))
#define ASN1_TIME_FRACTIONAL ((uint32_t)(1u << 3))
#define ASN1_TIME_LOCAL ((uint32_t)(1u << 4))

/*
 * 结构化时间。struct_size 必须为 sizeof(asn1_time_t)。
 * 时间三态：HAS_OFFSET 表示显式偏移，LOCAL 表示本地时间且无偏移，
 * 两者都不置位表示 Z。
 */
typedef struct asn1_time {
    size_t struct_size;                 /* 输入：必须为 sizeof(asn1_time_t) */
    int32_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
    uint8_t reserved_flags;             /* 必须置零（输出恒为 0） */
    int16_t utc_offset_minutes;         /* 仅 HAS_OFFSET 时有效 */
    uint32_t nanosecond;                /* 0..999,999,999；仅 FRACTIONAL 时有效 */
    uint32_t flags;                     /* ASN1_TIME_* */
} asn1_time_t;

#ifdef __cplusplus
extern "C" {
#endif

/* 文档与节点只读访问。 */
ASN1_API const asn1_node_t   *asn1_doc_root(const asn1_doc_t *doc);
ASN1_API asn1_encoding_t      asn1_doc_source_encoding(const asn1_doc_t *doc);
ASN1_API asn1_tag_class_t     asn1_node_tag_class(const asn1_node_t *node);
ASN1_API uint32_t             asn1_node_tag_number(const asn1_node_t *node);
ASN1_API asn1_encoding_form_t asn1_node_encoding_form(const asn1_node_t *node);
ASN1_API int                  asn1_node_is_indefinite(const asn1_node_t *node);
ASN1_API size_t               asn1_node_child_count(const asn1_node_t *node);
ASN1_API const asn1_node_t   *asn1_node_child_at(const asn1_node_t *node,
                                                 size_t index);
ASN1_API const asn1_node_t   *asn1_node_child_by_name(const asn1_node_t *node,
                                                      const char *field_name);
ASN1_API const char          *asn1_node_field_name(const asn1_node_t *node);
ASN1_API const asn1_node_t   *asn1_node_parent(const asn1_node_t *node);
ASN1_API asn1_err_t asn1_node_content(const asn1_node_t *node,
                                      const uint8_t **out_data,
                                      size_t *out_size);
ASN1_API const uint8_t       *asn1_node_tlv(const asn1_node_t *node,
                                            size_t *out_size);
ASN1_API size_t               asn1_node_offset(const asn1_node_t *node);

/* 语义读取：失败返回错误码，且不写部分输出。 */
ASN1_API asn1_err_t asn1_node_get_bool(const asn1_node_t *node, int *out_value);
ASN1_API asn1_err_t asn1_node_get_int64(const asn1_node_t *node, int64_t *out_value);
ASN1_API asn1_err_t asn1_node_get_octets(const asn1_node_t *node,
                                         const uint8_t **out_data,
                                         size_t *out_size);
ASN1_API asn1_err_t asn1_node_get_oid(const asn1_node_t *node,
                                      const char **out_dotted,
                                      size_t *out_size);
ASN1_API asn1_err_t asn1_node_get_bits(const asn1_node_t *node,
                                       const uint8_t **out_data,
                                       size_t *out_size,
                                       size_t *out_bit_length,
                                       uint8_t *out_unused_bits);
ASN1_API asn1_err_t asn1_node_get_raw_string(const asn1_node_t *node,
                                             const uint8_t **out_data,
                                             size_t *out_size);
ASN1_API asn1_err_t asn1_node_get_utf8(const asn1_node_t *node,
                                       const char **out_text,
                                       size_t *out_size);
ASN1_API asn1_err_t asn1_node_get_bigint_decimal(const asn1_node_t *node,
                                                 const char **out_text,
                                                 size_t *out_size);
ASN1_API asn1_err_t asn1_node_get_time(const asn1_node_t *node,
                                       asn1_time_t *out_time);

#ifdef __cplusplus
}
#endif

#endif /* ASN1_ASN1_NODE_H_INCLUDED */
