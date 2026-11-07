/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * schema 感知解码与编码：字段绑定、未知字段策略、DEFAULT 省略、CHOICE
 * 分派、OF 元素绑定、ANY 保留 TLV、约束求值、SET/SET OF 排序、
 * asn1_doc_validate 与真实证书的 ANY 实测。
 */
#include <asn1/asn1.h>

#include <stddef.h>
#include <string.h>

#include "../data/cert_ec_selfsigned.h"
#include "../data/cert_rsa_pss_selfsigned.h"
#include "../data/cert_rsa_selfsigned.h"
#include "check.h"

/* ---------- 辅助 ---------- */

static int bytes_equal(const uint8_t *actual, size_t actual_size,
                       const uint8_t *expected, size_t expected_size)
{
    if (actual_size != expected_size) {
        return 0;
    }
    return memcmp(actual, expected, expected_size) == 0;
}

static asn1_type_desc_t make_type(const char *name, asn1_type_kind_t kind,
                                  asn1_tag_class_t tag_class,
                                  uint32_t tag_number, asn1_tag_mode_t mode,
                                  uint32_t element_type_id)
{
    asn1_type_desc_t desc;
    memset(&desc, 0, sizeof(desc));
    desc.struct_size = sizeof(desc);
    desc.name = name;
    desc.kind = kind;
    desc.tag_class = tag_class;
    desc.tag_number = tag_number;
    desc.tag_mode = mode;
    desc.element_type_id = element_type_id;
    return desc;
}

static asn1_field_desc_t make_field(const char *name, uint32_t type_id,
                                    uint32_t flags)
{
    asn1_field_desc_t desc;
    memset(&desc, 0, sizeof(desc));
    desc.struct_size = sizeof(desc);
    desc.name = name;
    desc.type_id = type_id;
    desc.flags = flags;
    return desc;
}

static asn1_bound_t make_bound(int64_t value)
{
    asn1_bound_t bound;
    memset(&bound, 0, sizeof(bound));
    bound.struct_size = sizeof(bound);
    bound.value = value;
    return bound;
}

static asn1_bound_t make_decimal_bound(const char *text)
{
    asn1_bound_t bound;
    memset(&bound, 0, sizeof(bound));
    bound.struct_size = sizeof(bound);
    bound.decimal = text;
    bound.decimal_size = strlen(text);
    return bound;
}

static asn1_constraint_t make_range(int64_t lower, int64_t upper)
{
    asn1_constraint_t constraint;
    memset(&constraint, 0, sizeof(constraint));
    constraint.struct_size = sizeof(constraint);
    constraint.kind = ASN1_CONSTRAINT_RANGE;
    constraint.lower = make_bound(lower);
    constraint.upper = make_bound(upper);
    return constraint;
}

static asn1_constraint_t make_size(int64_t lower, int64_t upper)
{
    asn1_constraint_t constraint;
    memset(&constraint, 0, sizeof(constraint));
    constraint.struct_size = sizeof(constraint);
    constraint.kind = ASN1_CONSTRAINT_SIZE;
    constraint.lower = make_bound(lower);
    constraint.upper = make_bound(upper);
    return constraint;
}

/* 解码并返回文档；失败时断言所在用例已由调用方检查。 */
static asn1_err_t decode_schema(asn1_ctx_t *ctx, const asn1_schema_t *schema,
                                const uint8_t *data, size_t size,
                                uint32_t flags, asn1_doc_t **out_doc)
{
    asn1_decode_options_t options;
    asn1_decode_options_init(&options);
    options.encoding = ASN1_ENCODING_BER;
    options.flags = flags;
    size_t consumed = 0;
    return asn1_decode_buffer_with_schema(ctx, data, size, schema, &options,
                                          out_doc, &consumed);
}

static asn1_err_t encode_both(asn1_ctx_t *ctx, const asn1_schema_t *schema,
                              const asn1_doc_t *doc, uint8_t *schemaOut,
                              size_t schemaCapacity, size_t *schemaSize,
                              uint8_t *genericOut, size_t genericCapacity,
                              size_t *genericSize)
{
    asn1_buf_t buf;
    memset(&buf, 0, sizeof(buf));

    asn1_encode_options_t withSchema;
    asn1_encode_options_init(&withSchema);
    withSchema.schema = schema;
    const asn1_err_t rc = asn1_encode_buffer(ctx, doc, &withSchema, &buf);
    if (rc != ASN1_OK) {
        return rc;
    }
    if (buf.size > schemaCapacity) {
        asn1_buf_release(ctx, &buf);
        return ASN1_E_OUTPUT_LIMIT;
    }
    memcpy(schemaOut, buf.data, buf.size);
    *schemaSize = buf.size;
    asn1_buf_release(ctx, &buf);

    memset(&buf, 0, sizeof(buf));
    const asn1_err_t genericRc = asn1_encode_buffer(ctx, doc, NULL, &buf);
    if (genericRc != ASN1_OK) {
        return genericRc;
    }
    if (buf.size > genericCapacity) {
        asn1_buf_release(ctx, &buf);
        return ASN1_E_OUTPUT_LIMIT;
    }
    memcpy(genericOut, buf.data, buf.size);
    *genericSize = buf.size;
    asn1_buf_release(ctx, &buf);
    return ASN1_OK;
}

/* 用 STRICT_SCHEMA 对既有文档重新校验。 */
static asn1_err_t validate_strict(asn1_ctx_t *ctx, const asn1_doc_t *doc,
                                  const asn1_schema_t *schema)
{
    asn1_decode_options_t options;
    asn1_decode_options_init(&options);
    options.encoding = ASN1_ENCODING_BER;
    options.flags = ASN1_DECODE_STRICT_SCHEMA;
    asn1_ctx_clear_warnings(ctx);
    return asn1_doc_validate(ctx, doc, schema, &options);
}

/* ---------- 用例 ---------- */

int main(void)
{
    asn1_ctx_config_t config;
    asn1_ctx_config_init(&config);
    asn1_ctx_t *ctx = NULL;
    ASN1_TEST_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_OK);

    /* ===== 1. 字段绑定 + DEFAULT 省略 ===== */
    {
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t intId = 0;
        uint32_t seqId = 0;
        asn1_type_desc_t intType =
            make_type("Int", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 2,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &intType, &intId) ==
                        ASN1_OK);
        asn1_type_desc_t seqType =
            make_type("Pair", ASN1_TYPE_KIND_SEQUENCE, ASN1_TAG_UNIVERSAL, 16,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &seqType, &seqId) ==
                        ASN1_OK);
        asn1_field_desc_t aField = make_field("a", intId, 0);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, seqId, &aField) ==
                        ASN1_OK);
        static const uint8_t kDefaultZero[3] = {0x02, 0x01, 0x00};
        asn1_field_desc_t bField = make_field("b", intId, 0);
        bField.default_value = kDefaultZero;
        bField.default_value_size = sizeof(kDefaultZero);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, seqId, &bField) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, seqId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        /* 显式携带 DEFAULT 值：解码命名、编码按 DEFAULT 省略。 */
        static const uint8_t kWithDefault[8] = {0x30, 0x06, 0x02, 0x01,
                                                0x05, 0x02, 0x01, 0x00};
        static const uint8_t kOmitting[5] = {0x30, 0x03, 0x02, 0x01, 0x05};
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kWithDefault,
                                      sizeof(kWithDefault), 0, &doc) ==
                        ASN1_OK);
        const asn1_node_t *root = asn1_doc_root(doc);
        ASN1_TEST_CHECK(asn1_node_child_count(root) == 2);
        const asn1_node_t *a = asn1_node_child_by_name(root, "a");
        const asn1_node_t *b = asn1_node_child_by_name(root, "b");
        ASN1_TEST_CHECK(a != NULL && b != NULL);
        ASN1_TEST_CHECK(asn1_node_field_name(a) != NULL);
        int64_t value = 0;
        ASN1_TEST_CHECK(asn1_node_get_int64(a, &value) == ASN1_OK);
        ASN1_TEST_CHECK(value == 5);

        uint8_t schemaOut[16];
        uint8_t genericOut[16];
        size_t schemaSize = 0;
        size_t genericSize = 0;
        ASN1_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kOmitting,
                                    sizeof(kOmitting)));
        ASN1_TEST_CHECK(bytes_equal(genericOut, genericSize, kWithDefault,
                                    sizeof(kWithDefault)));
        asn1_doc_destroy(doc);

        /* 缺省 DEFAULT 字段：解码通过，编码保持省略。 */
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kOmitting, sizeof(kOmitting),
                                      0, &doc) == ASN1_OK);
        root = asn1_doc_root(doc);
        ASN1_TEST_CHECK(asn1_node_child_count(root) == 1);
        ASN1_TEST_CHECK(asn1_node_child_by_name(root, "a") != NULL);
        ASN1_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kOmitting,
                                    sizeof(kOmitting)));
        asn1_doc_destroy(doc);
        asn1_schema_destroy(schema);
    }

    /* ===== 2. 未知字段策略 ===== */
    {
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t intId = 0;
        uint32_t seqId = 0;
        asn1_type_desc_t intType =
            make_type("Int", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 2,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &intType, &intId) ==
                        ASN1_OK);
        asn1_type_desc_t seqType =
            make_type("OnlyA", ASN1_TYPE_KIND_SEQUENCE, ASN1_TAG_UNIVERSAL, 16,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &seqType, &seqId) ==
                        ASN1_OK);
        asn1_field_desc_t aField = make_field("a", intId, 0);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, seqId, &aField) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, seqId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kUnknown[8] = {0x30, 0x06, 0x02, 0x01,
                                            0x05, 0x04, 0x01, 0x00};
        asn1_doc_t *doc = NULL;
        /* 默认：静默保留。 */
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kUnknown, sizeof(kUnknown),
                                      0, &doc) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_child_count(asn1_doc_root(doc)) == 2);
        asn1_doc_destroy(doc);

        /* WARN：保留并产生一条告警，偏移指向未知字段。 */
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kUnknown, sizeof(kUnknown),
                                      ASN1_DECODE_WARN_UNKNOWN_FIELD,
                                      &doc) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_ctx_warning_count(ctx) == 1);
        asn1_warning_t warning;
        memset(&warning, 0, sizeof(warning));
        warning.struct_size = sizeof(warning);
        ASN1_TEST_CHECK(asn1_ctx_get_warning(ctx, 0, &warning) == ASN1_OK);
        ASN1_TEST_CHECK(warning.code == ASN1_E_SCHEMA_FIELD);
        ASN1_TEST_CHECK(warning.offset == 5);
        asn1_doc_destroy(doc);

        /* STRICT：立即失败并写入路径与偏移。 */
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kUnknown, sizeof(kUnknown),
                                      ASN1_DECODE_STRICT_SCHEMA, &doc) ==
                        ASN1_E_SCHEMA_FIELD);
        asn1_error_info_t info;
        memset(&info, 0, sizeof(info));
        info.struct_size = sizeof(info);
        ASN1_TEST_CHECK(asn1_ctx_get_error(ctx, &info) == ASN1_OK);
        ASN1_TEST_CHECK(info.code == ASN1_E_SCHEMA_FIELD);
        ASN1_TEST_CHECK(info.offset == 5);
        ASN1_TEST_CHECK(info.path != NULL);

        /* STRICT 与 WARN 同时设置：严格优先，不产生告警。 */
        asn1_ctx_clear_warnings(ctx);
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kUnknown, sizeof(kUnknown),
                                      ASN1_DECODE_STRICT_SCHEMA |
                                          ASN1_DECODE_WARN_UNKNOWN_FIELD,
                                      &doc) == ASN1_E_SCHEMA_FIELD);
        ASN1_TEST_CHECK(asn1_ctx_warning_count(ctx) == 0);
        asn1_schema_destroy(schema);
    }

    /* ===== 2b. 未知字段默认保留与严格校验 ===== */
    {
        asn1_schema_t *schema = NULL;
        uint32_t intId = 0;
        uint32_t seqId = 0;
        asn1_type_desc_t intType =
            make_type("Int", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 2,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &intType, &intId) ==
                        ASN1_OK);
        asn1_type_desc_t seqType =
            make_type("ExtSeq", ASN1_TYPE_KIND_SEQUENCE, ASN1_TAG_UNIVERSAL, 16,
                      ASN1_TAG_MODE_DEFAULT, 0);
        seqType.flags = ASN1_TYPE_EXTENSIBLE;
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &seqType, &seqId) ==
                        ASN1_OK);
        asn1_field_desc_t aField = make_field("a", intId, 0);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, seqId, &aField) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, seqId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kKnownFirst[8] = {0x30, 0x06, 0x02, 0x01,
                                               0x05, 0x04, 0x01, 0x00};
        static const uint8_t kUnknownFirst[8] = {0x30, 0x06, 0x04, 0x01,
                                                 0x00, 0x02, 0x01, 0x05};
        static const uint8_t kMultiUnknown[11] = {
            0x30, 0x09, 0x02, 0x01, 0x05, 0x04,
            0x01, 0x01, 0x04, 0x01, 0x02};
        uint8_t schemaOut[32];
        uint8_t genericOut[32];
        size_t schemaSize = 0;
        size_t genericSize = 0;
        asn1_doc_t *doc = NULL;

        /* extensible：已知在前、未知在后逐字节往返。 */
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kKnownFirst,
                                      sizeof(kKnownFirst), 0, &doc) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_child_count(asn1_doc_root(doc)) == 2);
        ASN1_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kKnownFirst,
                                    sizeof(kKnownFirst)));
        ASN1_TEST_CHECK(bytes_equal(genericOut, genericSize, kKnownFirst,
                                    sizeof(kKnownFirst)));
        ASN1_TEST_CHECK(validate_strict(ctx, doc, schema) ==
                        ASN1_E_SCHEMA_FIELD);
        asn1_error_info_t info;
        memset(&info, 0, sizeof(info));
        info.struct_size = sizeof(info);
        ASN1_TEST_CHECK(asn1_ctx_get_error(ctx, &info) == ASN1_OK);
        ASN1_TEST_CHECK(info.code == ASN1_E_SCHEMA_FIELD);
        ASN1_TEST_CHECK(info.offset == 5);
        ASN1_TEST_CHECK(info.path != NULL);
        asn1_doc_destroy(doc);

        /* 未知在前：schema 编码把已知字段前置，未知字段保持相对顺序。 */
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kUnknownFirst,
                                      sizeof(kUnknownFirst), 0, &doc) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kKnownFirst,
                                    sizeof(kKnownFirst)));
        ASN1_TEST_CHECK(bytes_equal(genericOut, genericSize, kUnknownFirst,
                                    sizeof(kUnknownFirst)));
        asn1_doc_destroy(doc);

        /* 多个未知字段之间不重排。 */
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kMultiUnknown,
                                      sizeof(kMultiUnknown), 0, &doc) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kMultiUnknown,
                                    sizeof(kMultiUnknown)));
        asn1_doc_destroy(doc);
        asn1_schema_destroy(schema);

        /* 非 extensible SEQUENCE：未知字段同样默认保留，严格路径报错。 */
        schema = NULL;
        intId = 0;
        seqId = 0;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &intType, &intId) ==
                        ASN1_OK);
        seqType = make_type("PlainSeq", ASN1_TYPE_KIND_SEQUENCE,
                            ASN1_TAG_UNIVERSAL, 16, ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &seqType, &seqId) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, seqId, &aField) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, seqId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kKnownFirst,
                                      sizeof(kKnownFirst), 0, &doc) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kKnownFirst,
                                    sizeof(kKnownFirst)));
        ASN1_TEST_CHECK(validate_strict(ctx, doc, schema) ==
                        ASN1_E_SCHEMA_FIELD);
        asn1_doc_destroy(doc);
        asn1_schema_destroy(schema);
    }

    /* ===== 2c. SET 未知字段：schema 编码拒绝 ===== */
    {
        asn1_schema_t *schema = NULL;
        uint32_t intId = 0;
        uint32_t setId = 0;
        asn1_type_desc_t intType =
            make_type("Int", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 2,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &intType, &intId) ==
                        ASN1_OK);
        asn1_type_desc_t setType =
            make_type("Bag", ASN1_TYPE_KIND_SET, ASN1_TAG_UNIVERSAL, 17,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &setType, &setId) ==
                        ASN1_OK);
        asn1_field_desc_t aField = make_field("a", intId, 0);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, setId, &aField) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, setId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kSetUnknown[8] = {0x31, 0x06, 0x02, 0x01,
                                               0x05, 0x04, 0x01, 0x00};
        static const uint8_t kSetKnown[5] = {0x31, 0x03, 0x02, 0x01, 0x05};
        asn1_doc_t *doc = NULL;
        asn1_buf_t buf;
        memset(&buf, 0, sizeof(buf));

        ASN1_TEST_CHECK(decode_schema(ctx, schema, kSetUnknown,
                                      sizeof(kSetUnknown), 0, &doc) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_child_count(asn1_doc_root(doc)) == 2);
        asn1_encode_options_t options;
        asn1_encode_options_init(&options);
        options.schema = schema;
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &options, &buf) ==
                        ASN1_E_SCHEMA_FIELD);
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(validate_strict(ctx, doc, schema) ==
                        ASN1_E_SCHEMA_FIELD);
        /* 无 schema 通用编码仍可写出（按 DER 规范化）。 */
        memset(&buf, 0, sizeof(buf));
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, kSetUnknown,
                                    sizeof(kSetUnknown)));
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        asn1_doc_destroy(doc);

        ASN1_TEST_CHECK(decode_schema(ctx, schema, kSetKnown, sizeof(kSetKnown),
                                      0, &doc) == ASN1_OK);
        memset(&buf, 0, sizeof(buf));
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &options, &buf) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, kSetKnown,
                                    sizeof(kSetKnown)));
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(validate_strict(ctx, doc, schema) == ASN1_OK);
        asn1_doc_destroy(doc);
        asn1_schema_destroy(schema);
    }

    /* ===== 2d. ANY 与保留 TLV 的 DER 一致性 ===== */
    {
        asn1_schema_t *schema = NULL;
        uint32_t anyId = 0;
        uint32_t boxId = 0;
        asn1_type_desc_t anyType =
            make_type("Open", ASN1_TYPE_KIND_ANY, ASN1_TAG_UNIVERSAL, 0,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &anyType, &anyId) ==
                        ASN1_OK);
        asn1_type_desc_t boxType =
            make_type("Box", ASN1_TYPE_KIND_SEQUENCE, ASN1_TAG_UNIVERSAL, 16,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &boxType, &boxId) ==
                        ASN1_OK);
        asn1_field_desc_t anyField = make_field("open", anyId, 0);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, boxId, &anyField) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, boxId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kNonMinimalAny[6] = {0x30, 0x04, 0x04,
                                                  0x81, 0x01, 0x00};
        static const uint8_t kIndefiniteAny[9] = {0x30, 0x07, 0x30, 0x80, 0x02,
                                                  0x01, 0x05, 0x00, 0x00};
        asn1_doc_t *doc = NULL;
        asn1_buf_t buf;

        /* 非最短长度 ANY：BER 可解码，schema 感知编码拒绝，通用编码原样回写。 */
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kNonMinimalAny,
                                      sizeof(kNonMinimalAny), 0, &doc) ==
                        ASN1_OK);
        memset(&buf, 0, sizeof(buf));
        asn1_encode_options_t options;
        asn1_encode_options_init(&options);
        options.schema = schema;
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &options, &buf) ==
                        ASN1_E_NON_CANONICAL);
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        memset(&buf, 0, sizeof(buf));
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, kNonMinimalAny,
                                    sizeof(kNonMinimalAny)));
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        asn1_doc_destroy(doc);

        /* BER 不定长 ANY：同上。 */
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kIndefiniteAny,
                                      sizeof(kIndefiniteAny), 0, &doc) ==
                        ASN1_OK);
        memset(&buf, 0, sizeof(buf));
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &options, &buf) ==
                        ASN1_E_NON_CANONICAL);
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        memset(&buf, 0, sizeof(buf));
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, kIndefiniteAny,
                                    sizeof(kIndefiniteAny)));
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        asn1_doc_destroy(doc);
        asn1_schema_destroy(schema);

        /* 未知字段的非规范 TLV：schema 路径拒绝，通用路径按 DER 规范化。 */
        schema = NULL;
        uint32_t intId = 0;
        uint32_t seqId = 0;
        asn1_type_desc_t intType =
            make_type("Int", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 2,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &intType, &intId) ==
                        ASN1_OK);
        asn1_type_desc_t seqType =
            make_type("PlainSeq", ASN1_TYPE_KIND_SEQUENCE, ASN1_TAG_UNIVERSAL,
                      16, ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &seqType, &seqId) ==
                        ASN1_OK);
        asn1_field_desc_t aField = make_field("a", intId, 0);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, seqId, &aField) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, seqId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);
        asn1_encode_options_init(&options);
        options.schema = schema;

        static const uint8_t kNonMinimalUnknown[9] = {
            0x30, 0x07, 0x02, 0x01, 0x05, 0x04, 0x81, 0x01, 0x00};
        static const uint8_t kNonMinimalUnknownGeneric[8] = {
            0x30, 0x06, 0x02, 0x01, 0x05, 0x04, 0x01, 0x00};
        static const uint8_t kIndefiniteUnknown[12] = {
            0x30, 0x0A, 0x02, 0x01, 0x05, 0x24,
            0x80, 0x02, 0x01, 0x05, 0x00, 0x00};
        static const uint8_t kIndefiniteUnknownGeneric[10] = {
            0x30, 0x08, 0x02, 0x01, 0x05, 0x24, 0x03, 0x02, 0x01, 0x05};
        static const uint8_t kLongTagUnknown[9] = {
            0x30, 0x07, 0x02, 0x01, 0x05, 0x1F, 0x02, 0x01, 0x05};
        static const uint8_t kLongTagUnknownGeneric[8] = {
            0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x05};

        ASN1_TEST_CHECK(decode_schema(ctx, schema, kNonMinimalUnknown,
                                      sizeof(kNonMinimalUnknown), 0, &doc) ==
                        ASN1_OK);
        memset(&buf, 0, sizeof(buf));
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &options, &buf) ==
                        ASN1_E_NON_CANONICAL);
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        memset(&buf, 0, sizeof(buf));
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size,
                                    kNonMinimalUnknownGeneric,
                                    sizeof(kNonMinimalUnknownGeneric)));
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        asn1_doc_destroy(doc);

        ASN1_TEST_CHECK(decode_schema(ctx, schema, kIndefiniteUnknown,
                                      sizeof(kIndefiniteUnknown), 0, &doc) ==
                        ASN1_OK);
        memset(&buf, 0, sizeof(buf));
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &options, &buf) ==
                        ASN1_E_NON_CANONICAL);
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        memset(&buf, 0, sizeof(buf));
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size,
                                    kIndefiniteUnknownGeneric,
                                    sizeof(kIndefiniteUnknownGeneric)));
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        asn1_doc_destroy(doc);

        ASN1_TEST_CHECK(decode_schema(ctx, schema, kLongTagUnknown,
                                      sizeof(kLongTagUnknown), 0, &doc) ==
                        ASN1_OK);
        memset(&buf, 0, sizeof(buf));
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &options, &buf) ==
                        ASN1_E_NON_CANONICAL);
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        memset(&buf, 0, sizeof(buf));
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, kLongTagUnknownGeneric,
                                    sizeof(kLongTagUnknownGeneric)));
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        asn1_doc_destroy(doc);
        asn1_schema_destroy(schema);
    }

    /* ===== 3. CHOICE 分派 ===== */
    {
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t intId = 0;
        uint32_t strId = 0;
        uint32_t choiceId = 0;
        asn1_type_desc_t intType =
            make_type("Int", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 2,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &intType, &intId) ==
                        ASN1_OK);
        asn1_type_desc_t strType =
            make_type("Str", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 12,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &strType, &strId) ==
                        ASN1_OK);
        asn1_type_desc_t choiceType =
            make_type("Choice", ASN1_TYPE_KIND_CHOICE, ASN1_TAG_UNIVERSAL, 0,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &choiceType, &choiceId) ==
                        ASN1_OK);
        asn1_field_desc_t intField = make_field("intValue", intId, 0);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, choiceId, &intField) ==
                        ASN1_OK);
        asn1_field_desc_t strField = make_field("textValue", strId, 0);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, choiceId, &strField) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, choiceId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kText[5] = {0x0C, 0x03, 0x61, 0x62, 0x63};
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kText, sizeof(kText), 0,
                                      &doc) == ASN1_OK);
        const asn1_node_t *root = asn1_doc_root(doc);
        ASN1_TEST_CHECK(root != NULL);
        const char *branch = asn1_node_field_name(root);
        ASN1_TEST_CHECK(branch != NULL);
        ASN1_TEST_CHECK(strcmp(branch, "textValue") == 0);
        const uint8_t *content = NULL;
        size_t contentSize = 0;
        ASN1_TEST_CHECK(asn1_node_content(root, &content, &contentSize) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(contentSize == 3);
        ASN1_TEST_CHECK(memcmp(content, "abc", 3) == 0);
        asn1_doc_destroy(doc);
        asn1_schema_destroy(schema);
    }

    /* ===== 4. OF 绑定与 SIZE 区分字节数/元素数 ===== */
    {
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t intId = 0;
        uint32_t ofId = 0;

        asn1_constraint_t sizeRange = make_size(1, 3);
        asn1_type_desc_t intType =
            make_type("Int", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 2,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &intType, &intId) ==
                        ASN1_OK);
        asn1_type_desc_t ofType =
            make_type("Ints", ASN1_TYPE_KIND_SEQUENCE_OF, ASN1_TAG_UNIVERSAL,
                      16, ASN1_TAG_MODE_DEFAULT, intId);
        ofType.constraints = &sizeRange;
        ofType.constraint_count = 1;
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &ofType, &ofId) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, ofId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kThree[11] = {0x30, 0x09, 0x02, 0x01, 0x01, 0x02,
                                           0x01, 0x02, 0x02, 0x01, 0x03};
        static const uint8_t kFour[14] = {0x30, 0x0C, 0x02, 0x01, 0x01, 0x02,
                                          0x01, 0x02, 0x02, 0x01, 0x03, 0x02,
                                          0x01, 0x04};
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kThree, sizeof(kThree), 0,
                                      &doc) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_child_count(asn1_doc_root(doc)) == 3);
        asn1_doc_destroy(doc);
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kFour, sizeof(kFour), 0,
                                      &doc) == ASN1_E_SCHEMA_CONSTRAINT);
        ASN1_TEST_CHECK(doc == NULL);
        asn1_schema_destroy(schema);
    }

    {
        /* OCTET STRING 的 SIZE 按字节数。 */
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t octId = 0;
        asn1_constraint_t sizeRange = make_size(2, 4);
        asn1_type_desc_t octType =
            make_type("Octets", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 4,
                      ASN1_TAG_MODE_DEFAULT, 0);
        octType.constraints = &sizeRange;
        octType.constraint_count = 1;
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &octType, &octId) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, octId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kOk[4] = {0x04, 0x02, 0xAA, 0xBB};
        static const uint8_t kTooLong[7] = {0x04, 0x05, 0xAA, 0xBB,
                                            0xCC, 0xDD, 0xEE};
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kOk, sizeof(kOk), 0,
                                      &doc) == ASN1_OK);
        asn1_doc_destroy(doc);
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kTooLong, sizeof(kTooLong),
                                      0, &doc) == ASN1_E_SCHEMA_CONSTRAINT);
        asn1_schema_destroy(schema);
    }

    /* ===== 5. RANGE / ENUM / MAX / BIGINT ===== */
    {
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t rangeId = 0;
        asn1_constraint_t range = make_range(0, 10);
        asn1_type_desc_t rangeType =
            make_type("Ranged", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 2,
                      ASN1_TAG_MODE_DEFAULT, 0);
        rangeType.constraints = &range;
        rangeType.constraint_count = 1;
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &rangeType, &rangeId) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, rangeId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kTen[3] = {0x02, 0x01, 0x0A};
        static const uint8_t kEleven[3] = {0x02, 0x01, 0x0B};
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kTen, sizeof(kTen), 0,
                                      &doc) == ASN1_OK);
        asn1_doc_destroy(doc);
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kEleven, sizeof(kEleven), 0,
                                      &doc) == ASN1_E_SCHEMA_CONSTRAINT);
        asn1_schema_destroy(schema);
    }

    {
        /* ENUM 与负值。 */
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        static const int64_t kValues[2] = {1, 3};
        asn1_constraint_t enumConstraint;
        memset(&enumConstraint, 0, sizeof(enumConstraint));
        enumConstraint.struct_size = sizeof(enumConstraint);
        enumConstraint.kind = ASN1_CONSTRAINT_ENUM;
        enumConstraint.enum_values = kValues;
        enumConstraint.enum_count = 2;
        uint32_t enumId = 0;
        asn1_type_desc_t enumType =
            make_type("Enum", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 2,
                      ASN1_TAG_MODE_DEFAULT, 0);
        enumType.constraints = &enumConstraint;
        enumType.constraint_count = 1;
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &enumType, &enumId) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, enumId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kOne[3] = {0x02, 0x01, 0x01};
        static const uint8_t kTwo[3] = {0x02, 0x01, 0x02};
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kOne, sizeof(kOne), 0,
                                      &doc) == ASN1_OK);
        asn1_doc_destroy(doc);
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kTwo, sizeof(kTwo), 0,
                                      &doc) == ASN1_E_SCHEMA_CONSTRAINT);
        asn1_schema_destroy(schema);
    }

    {
        /* MAX：下界 0、上界无界。 */
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        asn1_constraint_t maxConstraint;
        memset(&maxConstraint, 0, sizeof(maxConstraint));
        maxConstraint.struct_size = sizeof(maxConstraint);
        maxConstraint.kind = ASN1_CONSTRAINT_MAX;
        maxConstraint.lower = make_bound(0);
        asn1_bound_t upper;
        memset(&upper, 0, sizeof(upper));
        upper.struct_size = sizeof(upper);
        upper.is_unbounded = 1;
        maxConstraint.upper = upper;
        uint32_t maxId = 0;
        asn1_type_desc_t maxType =
            make_type("NonNegative", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL,
                      2, ASN1_TAG_MODE_DEFAULT, 0);
        maxType.constraints = &maxConstraint;
        maxType.constraint_count = 1;
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &maxType, &maxId) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, maxId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kZero[3] = {0x02, 0x01, 0x00};
        static const uint8_t kMinusOne[3] = {0x02, 0x01, 0xFF};
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kZero, sizeof(kZero), 0,
                                      &doc) == ASN1_OK);
        asn1_doc_destroy(doc);
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kMinusOne, sizeof(kMinusOne),
                                      0, &doc) == ASN1_E_SCHEMA_CONSTRAINT);
        asn1_schema_destroy(schema);
    }

    {
        /* BIGINT：超出 int64 的边界按十进制比较。 */
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        static const char kLower[] = "-9223372036854775808";
        static const char kUpper[] = "9223372036854775808";
        asn1_constraint_t bigint;
        memset(&bigint, 0, sizeof(bigint));
        bigint.struct_size = sizeof(bigint);
        bigint.kind = ASN1_CONSTRAINT_BIGINT_RANGE;
        bigint.lower = make_decimal_bound(kLower);
        bigint.upper = make_decimal_bound(kUpper);
        uint32_t bigId = 0;
        asn1_type_desc_t bigType =
            make_type("BigInt", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 2,
                      ASN1_TAG_MODE_DEFAULT, 0);
        bigType.constraints = &bigint;
        bigType.constraint_count = 1;
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &bigType, &bigId) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, bigId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        /* 2^63 = 0x8000000000000000，需前置 0x00 保证为非负。 */
        static const uint8_t kAtUpper[11] = {0x02, 0x09, 0x00, 0x80, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00, 0x00};
        static const uint8_t kAboveUpper[11] = {0x02, 0x09, 0x00, 0x80, 0x00,
                                                0x00, 0x00, 0x00, 0x00, 0x00,
                                                0x01};
        static const uint8_t kAtLower[10] = {0x02, 0x08, 0x80, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00, 0x00};
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kAtUpper, sizeof(kAtUpper),
                                      0, &doc) == ASN1_OK);
        asn1_doc_destroy(doc);
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kAtLower, sizeof(kAtLower),
                                      0, &doc) == ASN1_OK);
        asn1_doc_destroy(doc);
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kAboveUpper,
                                      sizeof(kAboveUpper), 0, &doc) ==
                        ASN1_E_SCHEMA_CONSTRAINT);
        asn1_schema_destroy(schema);
    }

    /* ===== 6. SET 与 SET OF 的 DER 排序 ===== */
    {
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t intId = 0;
        uint32_t octId = 0;
        uint32_t setId = 0;
        asn1_type_desc_t intType =
            make_type("Int", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 2,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &intType, &intId) ==
                        ASN1_OK);
        asn1_type_desc_t octType =
            make_type("Octets", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 4,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &octType, &octId) ==
                        ASN1_OK);
        asn1_type_desc_t setType =
            make_type("Bag", ASN1_TYPE_KIND_SET, ASN1_TAG_UNIVERSAL, 17,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &setType, &setId) ==
                        ASN1_OK);
        asn1_field_desc_t aField = make_field("a", intId, 0);
        asn1_field_desc_t bField = make_field("b", octId, 0);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, setId, &aField) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, setId, &bField) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, setId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kBagIn[9] = {0x31, 0x07, 0x04, 0x02, 0xAA,
                                          0xBB, 0x02, 0x01, 0x05};
        static const uint8_t kBagSorted[9] = {0x31, 0x07, 0x02, 0x01, 0x05,
                                              0x04, 0x02, 0xAA, 0xBB};
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kBagIn, sizeof(kBagIn), 0,
                                      &doc) == ASN1_OK);
        uint8_t schemaOut[16];
        uint8_t genericOut[16];
        size_t schemaSize = 0;
        size_t genericSize = 0;
        ASN1_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kBagSorted,
                                    sizeof(kBagSorted)));
        ASN1_TEST_CHECK(bytes_equal(genericOut, genericSize, kBagSorted,
                                    sizeof(kBagSorted)));
        asn1_doc_destroy(doc);
        asn1_schema_destroy(schema);
    }

    {
        /* SET 字段使用 context 标签：编码按完整 TLV（标签优先）排序，
         * 与 schema 字段声明顺序无关。 */
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t tag2Id = 0;
        uint32_t tag0Id = 0;
        uint32_t setId = 0;
        asn1_type_desc_t tag2Type =
            make_type("CtxTag2", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_CONTEXT, 2,
                      ASN1_TAG_MODE_IMPLICIT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &tag2Type, &tag2Id) ==
                        ASN1_OK);
        asn1_type_desc_t tag0Type =
            make_type("CtxTag0", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_CONTEXT, 0,
                      ASN1_TAG_MODE_IMPLICIT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &tag0Type, &tag0Id) ==
                        ASN1_OK);
        asn1_type_desc_t setType =
            make_type("CtxBag", ASN1_TYPE_KIND_SET, ASN1_TAG_UNIVERSAL, 17,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &setType, &setId) ==
                        ASN1_OK);
        /* 声明顺序故意与标签顺序相反，迫使编码器实际排序。 */
        asn1_field_desc_t tag2Field = make_field("late", tag2Id, 0);
        asn1_field_desc_t tag0Field = make_field("early", tag0Id, 0);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, setId, &tag2Field) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, setId, &tag0Field) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, setId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kIn[8] = {0x31, 0x06, 0x82, 0x01, 0x06,
                                       0x80, 0x01, 0x05};
        static const uint8_t kSorted[8] = {0x31, 0x06, 0x80, 0x01, 0x05,
                                           0x82, 0x01, 0x06};
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kIn, sizeof(kIn), 0,
                                      &doc) == ASN1_OK);
        uint8_t schemaOut[16];
        uint8_t genericOut[16];
        size_t schemaSize = 0;
        size_t genericSize = 0;
        ASN1_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kSorted,
                                    sizeof(kSorted)));
        ASN1_TEST_CHECK(bytes_equal(genericOut, genericSize, kSorted,
                                    sizeof(kSorted)));
        asn1_doc_destroy(doc);

        ASN1_TEST_CHECK(decode_schema(ctx, schema, kSorted, sizeof(kSorted), 0,
                                      &doc) == ASN1_OK);
        ASN1_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kSorted,
                                    sizeof(kSorted)));
        ASN1_TEST_CHECK(bytes_equal(genericOut, genericSize, kSorted,
                                    sizeof(kSorted)));
        asn1_doc_destroy(doc);
        asn1_schema_destroy(schema);
    }

    {
        /* SET OF INTEGER：编码按元素完整 TLV 排序。 */
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t intId = 0;
        uint32_t ofId = 0;
        asn1_type_desc_t intType =
            make_type("Int", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 2,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &intType, &intId) ==
                        ASN1_OK);
        asn1_type_desc_t ofType =
            make_type("IntSet", ASN1_TYPE_KIND_SET_OF, ASN1_TAG_UNIVERSAL, 17,
                      ASN1_TAG_MODE_DEFAULT, intId);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &ofType, &ofId) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, ofId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kIn[8] = {0x31, 0x06, 0x02, 0x01,
                                       0x06, 0x02, 0x01, 0x05};
        static const uint8_t kSorted[8] = {0x31, 0x06, 0x02, 0x01,
                                           0x05, 0x02, 0x01, 0x06};
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kIn, sizeof(kIn), 0,
                                      &doc) == ASN1_OK);
        uint8_t schemaOut[16];
        uint8_t genericOut[16];
        size_t schemaSize = 0;
        size_t genericSize = 0;
        ASN1_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kSorted,
                                    sizeof(kSorted)));
        ASN1_TEST_CHECK(bytes_equal(genericOut, genericSize, kSorted,
                                    sizeof(kSorted)));
        asn1_doc_destroy(doc);

        /* 已排序输入重新解码再编码：结果保持不变（排序幂等）。 */
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kSorted, sizeof(kSorted), 0,
                                      &doc) == ASN1_OK);
        ASN1_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kSorted,
                                    sizeof(kSorted)));
        ASN1_TEST_CHECK(bytes_equal(genericOut, genericSize, kSorted,
                                    sizeof(kSorted)));
        asn1_doc_destroy(doc);
        asn1_schema_destroy(schema);
    }

    {
        /* SET OF ANY：异构元素解码 + DER 排序回写。 */
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t anyId = 0;
        uint32_t ofId = 0;
        asn1_type_desc_t anyType =
            make_type("AnyType", ASN1_TYPE_KIND_ANY, ASN1_TAG_UNIVERSAL, 0,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &anyType, &anyId) ==
                        ASN1_OK);
        asn1_constraint_t sizeRange = make_size(1, 4);
        asn1_type_desc_t ofType =
            make_type("AttributeSet", ASN1_TYPE_KIND_SET_OF,
                      ASN1_TAG_UNIVERSAL, 17, ASN1_TAG_MODE_DEFAULT, anyId);
        ofType.constraints = &sizeRange;
        ofType.constraint_count = 1;
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &ofType, &ofId) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, ofId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kUnsorted[13] = {0x31, 0x0B, 0x05, 0x00, 0x02, 0x01,
                                              0x05, 0x04, 0x02, 0xAA, 0xBB, 0x30,
                                              0x00};
        static const uint8_t kSorted[13] = {0x31, 0x0B, 0x02, 0x01, 0x05, 0x04,
                                            0x02, 0xAA, 0xBB, 0x05, 0x00, 0x30,
                                            0x00};
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kUnsorted, sizeof(kUnsorted),
                                      0, &doc) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_child_count(asn1_doc_root(doc)) == 4);
        for (size_t i = 0; i < 4; ++i) {
            ASN1_TEST_CHECK(asn1_node_child_count(
                                asn1_node_child_at(asn1_doc_root(doc), i)) == 0);
        }
        uint8_t schemaOut[16];
        uint8_t genericOut[16];
        size_t schemaSize = 0;
        size_t genericSize = 0;
        ASN1_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kSorted,
                                    sizeof(kSorted)));
        ASN1_TEST_CHECK(bytes_equal(genericOut, genericSize, kSorted,
                                    sizeof(kSorted)));
        asn1_doc_destroy(doc);

        ASN1_TEST_CHECK(decode_schema(ctx, schema, kSorted, sizeof(kSorted), 0,
                                      &doc) == ASN1_OK);
        ASN1_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kSorted,
                                    sizeof(kSorted)));
        asn1_doc_destroy(doc);
        asn1_schema_destroy(schema);
    }

    /* ===== 7. EXPLICIT ANY 重新包装 ===== */
    {
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t oidId = 0;
        uint32_t anyId = 0;
        uint32_t valueId = 0;
        uint32_t seqId = 0;
        asn1_type_desc_t oidType =
            make_type("Oid", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 6,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &oidType, &oidId) ==
                        ASN1_OK);
        asn1_type_desc_t anyType =
            make_type("AnyType", ASN1_TYPE_KIND_ANY, ASN1_TAG_UNIVERSAL, 0,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &anyType, &anyId) ==
                        ASN1_OK);
        asn1_type_desc_t valueType =
            make_type("WrappedAny", ASN1_TYPE_KIND_ANY, ASN1_TAG_CONTEXT, 1,
                      ASN1_TAG_MODE_EXPLICIT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &valueType, &valueId) ==
                        ASN1_OK);
        asn1_type_desc_t seqType =
            make_type("WithWrapped", ASN1_TYPE_KIND_SEQUENCE,
                      ASN1_TAG_UNIVERSAL, 16, ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &seqType, &seqId) ==
                        ASN1_OK);
        asn1_field_desc_t idField = make_field("id", oidId, 0);
        asn1_field_desc_t valueField = make_field("value", valueId, 0);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, seqId, &idField) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, seqId, &valueField) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, seqId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        /* 内层为 OCTET STRING。 */
        static const uint8_t kOctetsIn[11] = {0x30, 0x09, 0x06, 0x01, 0x2A,
                                              0xA1, 0x04, 0x04, 0x02, 0xAA,
                                              0xBB};
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kOctetsIn, sizeof(kOctetsIn),
                                      0, &doc) == ASN1_OK);
        const asn1_node_t *root = asn1_doc_root(doc);
        const asn1_node_t *value = asn1_node_child_by_name(root, "value");
        ASN1_TEST_CHECK(value != NULL);
        ASN1_TEST_CHECK(asn1_node_child_count(value) == 0);
        size_t tlvSize = 0;
        const uint8_t *tlv = asn1_node_tlv(value, &tlvSize);
        ASN1_TEST_CHECK(tlvSize == 6);
        ASN1_TEST_CHECK(tlv != NULL && tlv[0] == 0xA1);
        const uint8_t *content = NULL;
        size_t contentSize = 0;
        ASN1_TEST_CHECK(asn1_node_content(value, &content, &contentSize) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(contentSize == 4);
        ASN1_TEST_CHECK(bytes_equal(content, contentSize, kOctetsIn + 7, 4));

        uint8_t schemaOut[16];
        uint8_t genericOut[16];
        size_t schemaSize = 0;
        size_t genericSize = 0;
        ASN1_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kOctetsIn,
                                    sizeof(kOctetsIn)));
        ASN1_TEST_CHECK(bytes_equal(genericOut, genericSize, kOctetsIn,
                                    sizeof(kOctetsIn)));
        asn1_doc_destroy(doc);

        /* 内层为 SEQUENCE。 */
        static const uint8_t kSeqIn[9] = {0x30, 0x07, 0x06, 0x01,
                                          0x2A, 0xA1, 0x02, 0x30, 0x00};
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kSeqIn, sizeof(kSeqIn), 0,
                                      &doc) == ASN1_OK);
        root = asn1_doc_root(doc);
        value = asn1_node_child_by_name(root, "value");
        ASN1_TEST_CHECK(value != NULL);
        ASN1_TEST_CHECK(asn1_node_child_count(value) == 0);
        ASN1_TEST_CHECK(asn1_node_content(value, &content, &contentSize) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(contentSize == 2);
        ASN1_TEST_CHECK(content[0] == 0x30 && content[1] == 0x00);
        ASN1_TEST_CHECK(encode_both(ctx, schema, doc, schemaOut,
                                    sizeof(schemaOut), &schemaSize, genericOut,
                                    sizeof(genericOut), &genericSize) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(schemaOut, schemaSize, kSeqIn,
                                    sizeof(kSeqIn)));
        asn1_doc_destroy(doc);
        asn1_schema_destroy(schema);
    }

    /* ===== 8. asn1_doc_validate ===== */
    {
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t intId = 0;
        uint32_t seqId = 0;
        asn1_type_desc_t intType =
            make_type("Int", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 2,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &intType, &intId) ==
                        ASN1_OK);
        asn1_type_desc_t seqType =
            make_type("Single", ASN1_TYPE_KIND_SEQUENCE, ASN1_TAG_UNIVERSAL, 16,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &seqType, &seqId) ==
                        ASN1_OK);
        asn1_field_desc_t aField = make_field("a", intId, 0);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, seqId, &aField) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, seqId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kGood[5] = {0x30, 0x03, 0x02, 0x01, 0x05};
        static const uint8_t kBadChild[5] = {0x30, 0x03, 0x04, 0x01, 0x05};
        static const uint8_t kBadRoot[5] = {0x31, 0x03, 0x02, 0x01, 0x05};
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kGood, sizeof(kGood), 0,
                                      &doc) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_validate(ctx, doc, schema, NULL) == ASN1_OK);
        asn1_doc_destroy(doc);

        size_t consumed = 0;
        /* 根标签不匹配：schema 类型错误。 */
        ASN1_TEST_CHECK(asn1_decode_buffer(ctx, kBadRoot, sizeof(kBadRoot),
                                           NULL, &doc, &consumed) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_validate(ctx, doc, schema, NULL) ==
                        ASN1_E_SCHEMA_TYPE);
        asn1_doc_destroy(doc);

        /* 必选字段缺失：schema 字段错误。 */
        ASN1_TEST_CHECK(asn1_decode_buffer(ctx, kBadChild, sizeof(kBadChild),
                                           NULL, &doc, &consumed) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_validate(ctx, doc, schema, NULL) ==
                        ASN1_E_SCHEMA_FIELD);
        asn1_doc_destroy(doc);
        asn1_schema_destroy(schema);
    }

    /* ===== 9. 真实证书：AlgorithmIdentifier.parameters 的 ANY ===== */
    {
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t oidId = 0;
        uint32_t anyId = 0;
        uint32_t algId = 0;
        uint32_t tbsId = 0;
        uint32_t bitStrId = 0;
        uint32_t certId = 0;
        asn1_type_desc_t oidType =
            make_type("Oid", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 6,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &oidType, &oidId) ==
                        ASN1_OK);
        asn1_type_desc_t anyType =
            make_type("AnyType", ASN1_TYPE_KIND_ANY, ASN1_TAG_UNIVERSAL, 0,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &anyType, &anyId) ==
                        ASN1_OK);
        asn1_type_desc_t algType =
            make_type("AlgorithmIdentifier", ASN1_TYPE_KIND_SEQUENCE,
                      ASN1_TAG_UNIVERSAL, 16, ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &algType, &algId) ==
                        ASN1_OK);
        asn1_field_desc_t algField = make_field("algorithm", oidId, 0);
        asn1_field_desc_t paramField =
            make_field("parameters", anyId, ASN1_FIELD_OPTIONAL);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, algId, &algField) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, algId, &paramField) ==
                        ASN1_OK);

        asn1_type_desc_t tbsType =
            make_type("TbsCertificate", ASN1_TYPE_KIND_SEQUENCE,
                      ASN1_TAG_UNIVERSAL, 16, ASN1_TAG_MODE_DEFAULT, 0);
        tbsType.flags = ASN1_TYPE_EXTENSIBLE;
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &tbsType, &tbsId) ==
                        ASN1_OK);
        asn1_type_desc_t bitType =
            make_type("BitString", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 3,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &bitType, &bitStrId) ==
                        ASN1_OK);
        asn1_type_desc_t certType =
            make_type("Certificate", ASN1_TYPE_KIND_SEQUENCE,
                      ASN1_TAG_UNIVERSAL, 16, ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &certType, &certId) ==
                        ASN1_OK);
        asn1_field_desc_t tbsField = make_field("tbsCertificate", tbsId, 0);
        asn1_field_desc_t sigField =
            make_field("signatureAlgorithm", algId, 0);
        asn1_field_desc_t valueField =
            make_field("signatureValue", bitStrId, 0);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, certId, &tbsField) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, certId, &sigField) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, certId, &valueField) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, certId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        asn1_doc_t *doc = NULL;

        /* RSA：parameters = NULL。 */
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kCertRsaSelfsigned,
                                      kCertRsaSelfsignedSize, 0, &doc) ==
                        ASN1_OK);
        const asn1_node_t *root = asn1_doc_root(doc);
        ASN1_TEST_CHECK(root != NULL);
        ASN1_TEST_CHECK(asn1_node_field_name(root) == NULL);
        const asn1_node_t *alg =
            asn1_node_child_by_name(root, "signatureAlgorithm");
        ASN1_TEST_CHECK(alg != NULL);
        ASN1_TEST_CHECK(asn1_node_child_count(alg) == 2);
        const asn1_node_t *params =
            asn1_node_child_by_name(alg, "parameters");
        ASN1_TEST_CHECK(params != NULL);
        ASN1_TEST_CHECK(asn1_node_child_count(params) == 0);
        size_t size = 0;
        const uint8_t *tlv = asn1_node_tlv(params, &size);
        ASN1_TEST_CHECK(size == 2);
        ASN1_TEST_CHECK(tlv != NULL && tlv[0] == 0x05 && tlv[1] == 0x00);
        asn1_doc_destroy(doc);

        /* RSA-PSS：parameters 为 SEQUENCE，ANY 不展开。 */
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kCertRsaPssSelfsigned,
                                      kCertRsaPssSelfsignedSize, 0, &doc) ==
                        ASN1_OK);
        root = asn1_doc_root(doc);
        alg = asn1_node_child_by_name(root, "signatureAlgorithm");
        ASN1_TEST_CHECK(alg != NULL);
        params = asn1_node_child_by_name(alg, "parameters");
        ASN1_TEST_CHECK(params != NULL);
        ASN1_TEST_CHECK(asn1_node_child_count(params) == 0);
        tlv = asn1_node_tlv(params, &size);
        ASN1_TEST_CHECK(size > 2);
        ASN1_TEST_CHECK(tlv != NULL && tlv[0] == 0x30);
        asn1_doc_destroy(doc);

        /* EC：ecdsa-with-SHA256 不带 parameters。 */
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kCertEcSelfsigned,
                                      kCertEcSelfsignedSize, 0, &doc) ==
                        ASN1_OK);
        root = asn1_doc_root(doc);
        alg = asn1_node_child_by_name(root, "signatureAlgorithm");
        ASN1_TEST_CHECK(alg != NULL);
        ASN1_TEST_CHECK(asn1_node_child_count(alg) == 1);
        ASN1_TEST_CHECK(asn1_node_child_by_name(alg, "parameters") == NULL);
        asn1_doc_destroy(doc);

        asn1_schema_destroy(schema);
    }

    /* ===== 10. 回归：ENUMERATED 与 IMPLICIT 标签的约束/绑定 ===== */
    {
        /* ENUMERATED（universal tag 10）参与 ENUM 约束求值。 */
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        static const int64_t kEnums[3] = {1, 3, 5};
        asn1_constraint_t enumConstraint;
        memset(&enumConstraint, 0, sizeof(enumConstraint));
        enumConstraint.struct_size = sizeof(enumConstraint);
        enumConstraint.kind = ASN1_CONSTRAINT_ENUM;
        enumConstraint.enum_values = kEnums;
        enumConstraint.enum_count = 3;
        uint32_t enumId = 0;
        asn1_type_desc_t enumType =
            make_type("Enum", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 10,
                      ASN1_TAG_MODE_DEFAULT, 0);
        enumType.constraints = &enumConstraint;
        enumType.constraint_count = 1;
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &enumType, &enumId) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, enumId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kEnumOk[3] = {0x0A, 0x01, 0x03};
        static const uint8_t kEnumBad[3] = {0x0A, 0x01, 0x02};
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kEnumOk, sizeof(kEnumOk), 0,
                                      &doc) == ASN1_OK);
        int64_t value = 0;
        ASN1_TEST_CHECK(asn1_node_get_int64(asn1_doc_root(doc), &value) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(value == 3);
        asn1_doc_destroy(doc);
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kEnumBad, sizeof(kEnumBad),
                                      0, &doc) == ASN1_E_SCHEMA_CONSTRAINT);
        asn1_schema_destroy(schema);
    }

    {
        /* IMPLICIT 隐式覆盖的 INTEGER：RANGE 约束按数值求值。 */
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        asn1_constraint_t range = make_range(0, 10);
        uint32_t intId = 0;
        asn1_type_desc_t intType =
            make_type("ImplicitInt", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_CONTEXT, 0,
                      ASN1_TAG_MODE_IMPLICIT, 0);
        intType.constraints = &range;
        intType.constraint_count = 1;
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &intType, &intId) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, intId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kImplicitOk[3] = {0x80, 0x01, 0x05};
        static const uint8_t kImplicitBad[3] = {0x80, 0x01, 0x0B};
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kImplicitOk,
                                      sizeof(kImplicitOk), 0, &doc) ==
                        ASN1_OK);
        /* 非通用标签节点不提供数值读取，直接核对内容。 */
        const uint8_t *content = NULL;
        size_t contentSize = 0;
        ASN1_TEST_CHECK(asn1_node_content(asn1_doc_root(doc), &content,
                                          &contentSize) == ASN1_OK);
        ASN1_TEST_CHECK(contentSize == 1 && content != NULL &&
                        content[0] == 0x05);
        asn1_doc_destroy(doc);
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kImplicitBad,
                                      sizeof(kImplicitBad), 0, &doc) ==
                        ASN1_E_SCHEMA_CONSTRAINT);
        asn1_schema_destroy(schema);
    }

    {
        /* IMPLICIT 隐式覆盖的 SEQUENCE：按类型自身标签匹配。 */
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t intId = 0;
        uint32_t seqId = 0;
        asn1_type_desc_t intType =
            make_type("Int", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 2,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &intType, &intId) ==
                        ASN1_OK);
        asn1_type_desc_t seqType =
            make_type("ImplicitSeq", ASN1_TYPE_KIND_SEQUENCE, ASN1_TAG_CONTEXT,
                      13, ASN1_TAG_MODE_IMPLICIT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &seqType, &seqId) ==
                        ASN1_OK);
        asn1_field_desc_t xField = make_field("x", intId, 0);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, seqId, &xField) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, seqId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kImplSeq[5] = {0xAD, 0x03, 0x02, 0x01, 0x05};
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kImplSeq, sizeof(kImplSeq),
                                      0, &doc) == ASN1_OK);
        const asn1_node_t *root = asn1_doc_root(doc);
        const asn1_node_t *x = asn1_node_child_by_name(root, "x");
        ASN1_TEST_CHECK(x != NULL);
        int64_t value = 0;
        ASN1_TEST_CHECK(asn1_node_get_int64(x, &value) == ASN1_OK);
        ASN1_TEST_CHECK(value == 5);
        asn1_doc_destroy(doc);
        asn1_schema_destroy(schema);
    }

    {
        /* IMPLICIT 覆盖的 SEQUENCE：schema 编码往返稳定在类型自身 context 标签。 */
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t intId = 0;
        uint32_t seqId = 0;
        asn1_type_desc_t intType =
            make_type("Int", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 2,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &intType, &intId) ==
                        ASN1_OK);
        asn1_type_desc_t seqType =
            make_type("ImplicitSeq", ASN1_TYPE_KIND_SEQUENCE, ASN1_TAG_CONTEXT,
                      13, ASN1_TAG_MODE_IMPLICIT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &seqType, &seqId) ==
                        ASN1_OK);
        asn1_field_desc_t xField = make_field("x", intId, 0);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, seqId, &xField) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, seqId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kImplSeq[5] = {0xAD, 0x03, 0x02, 0x01, 0x05};
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kImplSeq, sizeof(kImplSeq),
                                      0, &doc) == ASN1_OK);
        asn1_encode_options_t options;
        asn1_encode_options_init(&options);
        options.schema = schema;
        asn1_buf_t buf;
        memset(&buf, 0, sizeof(buf));
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &options, &buf) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, kImplSeq,
                                    sizeof(kImplSeq)));
        asn1_doc_destroy(doc);

        /* 编码结果再解码：字段值与原始输入一致。 */
        ASN1_TEST_CHECK(decode_schema(ctx, schema, buf.data, buf.size, 0,
                                      &doc) == ASN1_OK);
        const asn1_node_t *root = asn1_doc_root(doc);
        int64_t value = 0;
        ASN1_TEST_CHECK(asn1_node_get_int64(asn1_node_child_by_name(root, "x"),
                                            &value) == ASN1_OK);
        ASN1_TEST_CHECK(value == 5);
        asn1_doc_destroy(doc);
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        asn1_schema_destroy(schema);
    }

    {
        /* IMPLICIT 覆盖的 SET：schema 编码沿用 DER SET OF 排序并往返稳定。 */
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t intId = 0;
        uint32_t octId = 0;
        uint32_t setId = 0;
        asn1_type_desc_t intType =
            make_type("Int", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 2,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &intType, &intId) ==
                        ASN1_OK);
        asn1_type_desc_t octType =
            make_type("Octets", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 4,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &octType, &octId) ==
                        ASN1_OK);
        asn1_type_desc_t setType =
            make_type("ImplicitSet", ASN1_TYPE_KIND_SET, ASN1_TAG_CONTEXT, 14,
                      ASN1_TAG_MODE_IMPLICIT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &setType, &setId) ==
                        ASN1_OK);
        asn1_field_desc_t aField = make_field("a", intId, 0);
        asn1_field_desc_t bField = make_field("b", octId, 0);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, setId, &aField) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, setId, &bField) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, setId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kImplSet[8] = {0xAE, 0x06, 0x02, 0x01, 0x05,
                                            0x04, 0x01, 0x41};
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kImplSet, sizeof(kImplSet),
                                      0, &doc) == ASN1_OK);
        asn1_encode_options_t options;
        asn1_encode_options_init(&options);
        options.schema = schema;
        asn1_buf_t buf;
        memset(&buf, 0, sizeof(buf));
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &options, &buf) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, kImplSet,
                                    sizeof(kImplSet)));
        asn1_doc_destroy(doc);

        ASN1_TEST_CHECK(decode_schema(ctx, schema, buf.data, buf.size, 0,
                                      &doc) == ASN1_OK);
        const asn1_node_t *root = asn1_doc_root(doc);
        int64_t a = 0;
        const uint8_t *b = NULL;
        size_t bSize = 0;
        ASN1_TEST_CHECK(asn1_node_get_int64(asn1_node_child_by_name(root, "a"),
                                            &a) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_get_octets(asn1_node_child_by_name(root, "b"),
                                             &b, &bSize) == ASN1_OK);
        ASN1_TEST_CHECK(a == 5 && b != NULL && bSize == 1 && b[0] == 0x41);
        asn1_doc_destroy(doc);
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        asn1_schema_destroy(schema);
    }

    {
        /* IMPLICIT 覆盖的 SEQUENCE OF：schema 编码保持元素顺序并往返稳定。 */
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t intId = 0;
        uint32_t ofId = 0;
        asn1_type_desc_t intType =
            make_type("Int", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 2,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &intType, &intId) ==
                        ASN1_OK);
        asn1_type_desc_t ofType =
            make_type("ImplicitSeqOf", ASN1_TYPE_KIND_SEQUENCE_OF,
                      ASN1_TAG_CONTEXT, 15, ASN1_TAG_MODE_IMPLICIT, intId);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &ofType, &ofId) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, ofId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kImplSeqOf[8] = {0xAF, 0x06, 0x02, 0x01, 0x05,
                                              0x02, 0x01, 0x06};
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kImplSeqOf,
                                      sizeof(kImplSeqOf), 0, &doc) == ASN1_OK);
        asn1_encode_options_t options;
        asn1_encode_options_init(&options);
        options.schema = schema;
        asn1_buf_t buf;
        memset(&buf, 0, sizeof(buf));
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &options, &buf) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, kImplSeqOf,
                                    sizeof(kImplSeqOf)));
        asn1_doc_destroy(doc);

        ASN1_TEST_CHECK(decode_schema(ctx, schema, buf.data, buf.size, 0,
                                      &doc) == ASN1_OK);
        const asn1_node_t *root = asn1_doc_root(doc);
        ASN1_TEST_CHECK(asn1_node_child_count(root) == 2);
        int64_t first = 0;
        int64_t second = 0;
        ASN1_TEST_CHECK(asn1_node_get_int64(asn1_node_child_at(root, 0),
                                            &first) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_get_int64(asn1_node_child_at(root, 1),
                                            &second) == ASN1_OK);
        ASN1_TEST_CHECK(first == 5 && second == 6);
        asn1_doc_destroy(doc);
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        asn1_schema_destroy(schema);
    }

    {
        /* IMPLICIT 覆盖的 SET OF：[16] 反向输入经 schema 编码按 DER 排序，
         * 并稳定在类型自身 context 标签。 */
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t intId = 0;
        uint32_t ofId = 0;
        asn1_type_desc_t intType =
            make_type("Int", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 2,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &intType, &intId) ==
                        ASN1_OK);
        asn1_type_desc_t ofType =
            make_type("ImplicitSetOf", ASN1_TYPE_KIND_SET_OF,
                      ASN1_TAG_CONTEXT, 16, ASN1_TAG_MODE_IMPLICIT, intId);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &ofType, &ofId) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, ofId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kImplSetOfIn[8] = {0xB0, 0x06, 0x02, 0x01, 0x06,
                                                0x02, 0x01, 0x05};
        static const uint8_t kImplSetOfSorted[8] = {0xB0, 0x06, 0x02, 0x01,
                                                    0x05, 0x02, 0x01, 0x06};
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(decode_schema(ctx, schema, kImplSetOfIn,
                                      sizeof(kImplSetOfIn), 0, &doc) ==
                        ASN1_OK);
        asn1_encode_options_t options;
        asn1_encode_options_init(&options);
        options.schema = schema;
        asn1_buf_t buf;
        memset(&buf, 0, sizeof(buf));
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &options, &buf) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, kImplSetOfSorted,
                                    sizeof(kImplSetOfSorted)));
        asn1_doc_destroy(doc);

        ASN1_TEST_CHECK(decode_schema(ctx, schema, buf.data, buf.size, 0,
                                      &doc) == ASN1_OK);
        const asn1_node_t *root = asn1_doc_root(doc);
        ASN1_TEST_CHECK(asn1_node_child_count(root) == 2);
        int64_t first = 0;
        int64_t second = 0;
        ASN1_TEST_CHECK(asn1_node_get_int64(asn1_node_child_at(root, 0),
                                            &first) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_get_int64(asn1_node_child_at(root, 1),
                                            &second) == ASN1_OK);
        ASN1_TEST_CHECK(first == 5 && second == 6);
        asn1_doc_destroy(doc);
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        asn1_schema_destroy(schema);
    }

    {
        /* 高 tag 号按 base-128 变长编码；schema 编码与通用编码均往返稳定。 */
        static const uint8_t kTag31[4] = {0x9F, 0x1F, 0x01, 0x05};
        static const uint8_t kTag127[4] = {0x9F, 0x7F, 0x01, 0x05};
        static const uint8_t kTag128[5] = {0x9F, 0x81, 0x00, 0x01, 0x05};
        static const uint8_t kTag16383[5] = {0x9F, 0xFF, 0x7F, 0x01, 0x05};
        static const uint8_t kTag16384[6] = {0x9F, 0x81, 0x80, 0x00,
                                             0x01, 0x05};
        static const uint8_t kTag2097151[6] = {0x9F, 0xFF, 0xFF, 0x7F,
                                               0x01, 0x05};
        static const uint8_t kTagMax[8] = {0x9F, 0x8F, 0xFF, 0xFF, 0xFF,
                                           0x7F, 0x01, 0x05};

        struct HighTagCase {
            uint32_t number;
            const uint8_t *tlv;
            size_t size;
        };
        static const struct HighTagCase kCases[] = {
            {31, kTag31, sizeof(kTag31)},
            {127, kTag127, sizeof(kTag127)},
            {128, kTag128, sizeof(kTag128)},
            {16383, kTag16383, sizeof(kTag16383)},
            {16384, kTag16384, sizeof(kTag16384)},
            {2097151, kTag2097151, sizeof(kTag2097151)},
            {4294967295u, kTagMax, sizeof(kTagMax)},
        };

        for (size_t i = 0; i < sizeof(kCases) / sizeof(kCases[0]); ++i) {
            asn1_schema_t *schema = NULL;
            ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                               &schema) == ASN1_OK);
            uint32_t typeId = 0;
            asn1_type_desc_t type =
                make_type("HighTag", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_CONTEXT,
                          kCases[i].number, ASN1_TAG_MODE_IMPLICIT, 0);
            ASN1_TEST_CHECK(asn1_schema_add_type(schema, &type, &typeId) ==
                            ASN1_OK);
            ASN1_TEST_CHECK(asn1_schema_set_root(schema, typeId) == ASN1_OK);
            ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

            asn1_doc_t *doc = NULL;
            ASN1_TEST_CHECK(decode_schema(ctx, schema, kCases[i].tlv,
                                          kCases[i].size, 0, &doc) == ASN1_OK);
            asn1_encode_options_t options;
            asn1_encode_options_init(&options);
            options.schema = schema;
            asn1_buf_t buf;
            memset(&buf, 0, sizeof(buf));
            ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &options, &buf) ==
                            ASN1_OK);
            ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, kCases[i].tlv,
                                        kCases[i].size));
            asn1_doc_destroy(doc);

            /* 编码结果再解码：内容字节与原始输入一致。 */
            ASN1_TEST_CHECK(decode_schema(ctx, schema, buf.data, buf.size, 0,
                                          &doc) == ASN1_OK);
            const uint8_t *content = NULL;
            size_t contentSize = 0;
            ASN1_TEST_CHECK(asn1_node_content(asn1_doc_root(doc), &content,
                                              &contentSize) == ASN1_OK);
            ASN1_TEST_CHECK(content != NULL && contentSize == 1 &&
                            content[0] == 0x05);
            asn1_doc_destroy(doc);
            ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);

            /* 通用编码（无 schema）同样按 base-128 写出。 */
            ASN1_TEST_CHECK(decode_schema(ctx, schema, kCases[i].tlv,
                                          kCases[i].size, 0, &doc) == ASN1_OK);
            memset(&buf, 0, sizeof(buf));
            ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, &buf) ==
                            ASN1_OK);
            ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, kCases[i].tlv,
                                        kCases[i].size));
            asn1_doc_destroy(doc);
            ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
            asn1_schema_destroy(schema);
        }
    }

    asn1_ctx_destroy(ctx);
    return 0;
}
