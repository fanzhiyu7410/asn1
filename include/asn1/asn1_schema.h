/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 模板机制：类型树、约束、描述表加载、运行时注册与 schema 感知解码/校验。
 * 契约见 docs/02-C-API规范.md 5.2、5.4、6.2 与 docs/11-描述表格式.md。
 */
#ifndef ASN1_ASN1_SCHEMA_H_INCLUDED
#define ASN1_ASN1_SCHEMA_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include <asn1/asn1_allocator.h>
#include <asn1/asn1_build.h>
#include <asn1/asn1_decode.h>
#include <asn1/asn1_error.h>
#include <asn1/asn1_export.h>

typedef struct asn1_schema asn1_schema_t;

/* 类型种类；构造性由 kind 派生。 */
typedef enum asn1_type_kind {
    ASN1_TYPE_KIND_SIMPLE = 0,
    ASN1_TYPE_KIND_SEQUENCE = 1,
    ASN1_TYPE_KIND_SET = 2,
    ASN1_TYPE_KIND_CHOICE = 3,
    ASN1_TYPE_KIND_SEQUENCE_OF = 4,
    ASN1_TYPE_KIND_SET_OF = 5,
    /* 开放类型：保留完整原始 TLV，不展开；不使用自身 tag。 */
    ASN1_TYPE_KIND_ANY = 6
} asn1_type_kind_t;

/* 类型级标注方式；DEFAULT 继承模块级默认标注方式。 */
typedef enum asn1_tag_mode {
    ASN1_TAG_MODE_DEFAULT = 0,
    ASN1_TAG_MODE_EXPLICIT = 1,
    ASN1_TAG_MODE_IMPLICIT = 2
} asn1_tag_mode_t;

/* 类型标志。 */
#define ASN1_TYPE_EXTENSIBLE ((uint32_t)(1u << 0))

/* 字段标志。 */
#define ASN1_FIELD_OPTIONAL ((uint32_t)(1u << 0))
#define ASN1_FIELD_EXTENSION ((uint32_t)(1u << 1))

/*
 * 已编译描述表。struct_size 必须为 sizeof(asn1_schema_table_t)；
 * data 为 asn1c 生成的 C 数组或二进制资源，size 为其字节数；
 * format_version 为 (major << 16) | minor；reserved 必须置零。
 */
typedef struct asn1_schema_table {
    size_t struct_size;
    const void *data;
    size_t size;
    uint32_t format_version;
    uint32_t reserved;
} asn1_schema_table_t;

/* 约束边界。is_unbounded = 1 表示无界，忽略 value/decimal。 */
typedef struct asn1_bound {
    size_t struct_size;
    int32_t is_unbounded;
    int32_t reserved;
    int64_t value;
    const char *decimal;
    size_t decimal_size;
} asn1_bound_t;

typedef enum asn1_constraint_kind {
    ASN1_CONSTRAINT_RANGE = 0,
    ASN1_CONSTRAINT_SIZE = 1,
    ASN1_CONSTRAINT_ENUM = 2,
    ASN1_CONSTRAINT_MAX = 3,
    ASN1_CONSTRAINT_BIGINT_RANGE = 4
} asn1_constraint_kind_t;

/*
 * 约束。kind 取 asn1_constraint_kind_t；flags 必须为 0；
 * enum_values/enum_count 仅在 ENUM 时有效。
 */
typedef struct asn1_constraint {
    size_t struct_size;
    asn1_constraint_kind_t kind;
    uint32_t flags;
    asn1_bound_t lower;
    asn1_bound_t upper;
    const int64_t *enum_values;
    uint32_t enum_count;
    uint32_t reserved[2];
} asn1_constraint_t;

/*
 * 类型描述。type_id 由 asn1_schema_add_type 分配；element_type_id 仅对
 * SEQUENCE_OF/SET_OF 有效，其余必须为 0；ANY 必须 tag_class = UNIVERSAL、
 * tag_number = 0、tag_mode = DEFAULT、element_type_id = 0 且无约束；
 * flags 只接受 ASN1_TYPE_EXTENSIBLE。
 */
typedef struct asn1_type_desc {
    size_t struct_size;
    const char *name;
    asn1_type_kind_t kind;
    asn1_tag_class_t tag_class;
    uint32_t tag_number;
    asn1_tag_mode_t tag_mode;
    uint32_t element_type_id;
    uint32_t flags;
    const asn1_constraint_t *constraints;
    uint32_t constraint_count;
    uint32_t reserved[2];
} asn1_type_desc_t;

/*
 * 字段描述。type_id 必须是已注册类型；default_value 为规范 DER TLV，
 * 非空且 size 非 0 表示 DEFAULT；flags 只接受 ASN1_FIELD_OPTIONAL 与
 * ASN1_FIELD_EXTENSION 的组合。
 */
typedef struct asn1_field_desc {
    size_t struct_size;
    const char *name;
    uint32_t type_id;
    uint32_t flags;
    const void *default_value;
    size_t default_value_size;
    const asn1_constraint_t *field_constraints;
    uint32_t field_constraint_count;
    uint32_t reserved[2];
} asn1_field_desc_t;

/*
 * 命名位 / 名值记录。type_id 为所属类型；kind 取
 * ASN1_SCHEMA_NAME_KIND_BIT（BIT STRING 命名位）或
 * ASN1_SCHEMA_NAME_KIND_NUMBER（数值名）；flags 位 0 为
 * ASN1_SCHEMA_NAME_FLAG_EXTENSION；value 为位号或整数值。
 */
typedef struct asn1_schema_name_info {
    uint32_t struct_size;   /* 输入：必须为 sizeof(asn1_schema_name_info_t) */
    uint32_t type_id;
    uint32_t kind;          /* ASN1_SCHEMA_NAME_KIND_BIT / _NUMBER */
    uint32_t flags;         /* ASN1_SCHEMA_NAME_FLAG_EXTENSION */
    int64_t value;
    const char *name;       /* 借用，schema 存活期间有效 */
} asn1_schema_name_info_t;

#define ASN1_SCHEMA_NAME_KIND_BIT 0u
#define ASN1_SCHEMA_NAME_KIND_NUMBER 1u
#define ASN1_SCHEMA_NAME_FLAG_EXTENSION 1u

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 创建空类型树，供运行时注册。default_tag_mode 只接受 DEFAULT/EXPLICIT/
 * IMPLICIT；AUTOMATIC TAGS 在生成期已归一为 IMPLICIT，由调用方按 IMPLICIT
 * 传入。失败时 *out_schema 置 NULL。
 */
ASN1_API asn1_err_t asn1_schema_create(asn1_ctx_t *ctx,
                                       asn1_tag_mode_t default_tag_mode,
                                       asn1_schema_t **out_schema);

/*
 * 从描述表构建类型树并立即封存；模块默认标注方式取自描述表头部。
 * 失败时 *out_schema 置 NULL，不留下部分类型树。
 */
ASN1_API asn1_err_t asn1_schema_load(asn1_ctx_t *ctx,
                                     const asn1_schema_table_t *table,
                                     asn1_schema_t **out_schema);

/*
 * 追加类型，返回从 1 开始连续分配的类型编号。sealed 后返回
 * ASN1_E_INVALID_STATE；描述符内容复制进 schema。
 */
ASN1_API asn1_err_t asn1_schema_add_type(asn1_schema_t *schema,
                                         const asn1_type_desc_t *desc,
                                         uint32_t *out_type_id);

/*
 * 把字段追加到 parent_type_id 类型末尾。parent_type_id 必须已注册；
 * 描述符内容复制进 schema。
 */
ASN1_API asn1_err_t asn1_schema_add_field(asn1_schema_t *schema,
                                          uint32_t parent_type_id,
                                          const asn1_field_desc_t *desc);

/*
 * 命名位 / 名值只读查询。schema 必须已封存；运行时注册得到的 schema
 * 没有名称，全部查询返回“无名称”。type_id 必须为 1..type_count。
 * 字符串借用 schema，schema 销毁后失效。
 */
ASN1_API asn1_err_t asn1_schema_name_count(const asn1_schema_t *schema,
                                           uint32_t type_id,
                                           uint32_t *out_count);
ASN1_API asn1_err_t asn1_schema_name_at(const asn1_schema_t *schema,
                                        uint32_t type_id, uint32_t index,
                                        asn1_schema_name_info_t *out_info);

/* 按位号 / 整数值查名称；未命中返回 ASN1_OK 且 *out_name = NULL。 */
ASN1_API asn1_err_t asn1_schema_name_for_bit(const asn1_schema_t *schema,
                                             uint32_t type_id, uint32_t bit,
                                             const char **out_name);
ASN1_API asn1_err_t asn1_schema_name_for_value(const asn1_schema_t *schema,
                                               uint32_t type_id, int64_t value,
                                               const char **out_name);

/*
 * 按名称查数值（任意 kind）。命中返回 ASN1_OK 且 *out_found = 1；
 * 未命中返回 ASN1_OK、*out_found = 0、*out_value = 0。
 */
ASN1_API asn1_err_t asn1_schema_value_for_name(const asn1_schema_t *schema,
                                               uint32_t type_id,
                                               const char *name,
                                               int64_t *out_value,
                                               int *out_found);

/*
 * 设置单一根类型；root_type_id == 0 表示清除根（允许多个顶层类型并列）。
 * 非 0 必须在 1..type_count 内，否则返回 ASN1_E_SCHEMA_TYPE。
 * schema 已封存返回 ASN1_E_INVALID_STATE；schema 为 NULL 返回 ASN1_E_INVALID_ARG。
 */
ASN1_API asn1_err_t asn1_schema_set_root(asn1_schema_t *schema,
                                         uint32_t root_type_id);

/*
 * 冻结类型树并校验。成功后再调用返回 ASN1_OK（幂等）；失败时 schema
 * 保持未封存，可继续修正或销毁。
 */
ASN1_API asn1_err_t asn1_schema_seal(asn1_schema_t *schema);

/* 销毁 schema；schema == NULL 为空操作。 */
ASN1_API void asn1_schema_destroy(asn1_schema_t *schema);

/*
 * schema 感知解码：先按 BER/DER 解析，再按 schema 绑定字段、校验类型与
 * 约束，并把字段名复制进文档 arena。schema 必须已封存且设置了根类型；
 * 字段名在解码后仍有效，schema 可随即销毁。
 */
ASN1_API asn1_err_t asn1_decode_buffer_with_schema(
                                        asn1_ctx_t *ctx,
                                        const uint8_t *data, size_t size,
                                        const asn1_schema_t *schema,
                                        const asn1_decode_options_t *options,
                                        asn1_doc_t **out_doc,
                                        size_t *consumed);
ASN1_API asn1_err_t asn1_decode_reader_with_schema(
                                        asn1_ctx_t *ctx,
                                        const asn1_reader_t *reader,
                                        const asn1_schema_t *schema,
                                        const asn1_decode_options_t *options,
                                        asn1_doc_t **out_doc,
                                        size_t *consumed);

/* 对既有文档按 schema 重新校验；不修改节点。 */
ASN1_API asn1_err_t asn1_doc_validate(asn1_ctx_t *ctx,
                                      const asn1_doc_t *doc,
                                      const asn1_schema_t *schema,
                                      const asn1_decode_options_t *options);

#ifdef __cplusplus
}
#endif

#endif /* ASN1_ASN1_SCHEMA_H_INCLUDED */
