/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * runtime ANY 构树入口 asn1_node_create_any：合法性判定、字节复制与所有权、
 * 节点元数据推导、禁止子节点，以及 schema / 无 schema 两条编码路径的
 * 逐字节往返。
 */
#include <asn1/asn1.h>

#include <stddef.h>
#include <string.h>

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

static asn1_field_desc_t make_field(const char *name, uint32_t type_id)
{
    asn1_field_desc_t desc;
    memset(&desc, 0, sizeof(desc));
    desc.struct_size = sizeof(desc);
    desc.name = name;
    desc.type_id = type_id;
    return desc;
}

/* 构建 SEQUENCE { OID, ANY } 最小架构，根为 SEQUENCE。 */
static asn1_schema_t *make_algorithm_schema(asn1_ctx_t *ctx)
{
    asn1_schema_t *schema = NULL;
    if (asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT, &schema) != ASN1_OK) {
        return NULL;
    }
    uint32_t oid_id = 0;
    asn1_type_desc_t oid_type =
        make_type("Oid", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 6,
                  ASN1_TAG_MODE_DEFAULT, 0);
    if (asn1_schema_add_type(schema, &oid_type, &oid_id) != ASN1_OK) {
        asn1_schema_destroy(schema);
        return NULL;
    }
    uint32_t any_id = 0;
    asn1_type_desc_t any_type =
        make_type("AnyValue", ASN1_TYPE_KIND_ANY, ASN1_TAG_UNIVERSAL, 0,
                  ASN1_TAG_MODE_DEFAULT, 0);
    if (asn1_schema_add_type(schema, &any_type, &any_id) != ASN1_OK) {
        asn1_schema_destroy(schema);
        return NULL;
    }
    uint32_t seq_id = 0;
    asn1_type_desc_t seq_type =
        make_type("AlgorithmIdentifier", ASN1_TYPE_KIND_SEQUENCE,
                  ASN1_TAG_UNIVERSAL, 16, ASN1_TAG_MODE_DEFAULT, 0);
    if (asn1_schema_add_type(schema, &seq_type, &seq_id) != ASN1_OK) {
        asn1_schema_destroy(schema);
        return NULL;
    }
    asn1_field_desc_t algorithm = make_field("algorithm", oid_id);
    if (asn1_schema_add_field(schema, seq_id, &algorithm) != ASN1_OK) {
        asn1_schema_destroy(schema);
        return NULL;
    }
    asn1_field_desc_t parameters = make_field("parameters", any_id);
    if (asn1_schema_add_field(schema, seq_id, &parameters) != ASN1_OK ||
        asn1_schema_set_root(schema, seq_id) != ASN1_OK ||
        asn1_schema_seal(schema) != ASN1_OK) {
        asn1_schema_destroy(schema);
        return NULL;
    }
    return schema;
}

static int encode_compare(asn1_ctx_t *ctx, asn1_doc_t *doc,
                          const asn1_schema_t *schema,
                          const uint8_t *expected, size_t expected_size)
{
    asn1_encode_options_t options;
    asn1_encode_options_init(&options);
    options.schema = schema;

    asn1_buf_t buf;
    memset(&buf, 0, sizeof(buf));
    ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &options, &buf) == ASN1_OK);
    ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, expected, expected_size));
    ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
    return 0;
}

/* 校验节点元数据与保留字节。 */
static int check_any_metadata(const asn1_node_t *node, asn1_tag_class_t tag_class,
                              uint32_t tag_number, int constructed,
                              const uint8_t *tlv, size_t tlv_size,
                              size_t content_size)
{
    size_t actual_tlv_size = 0;
    const uint8_t *actual_tlv = asn1_node_tlv(node, &actual_tlv_size);
    ASN1_TEST_CHECK(actual_tlv != NULL);
    ASN1_TEST_CHECK(actual_tlv_size == tlv_size);
    ASN1_TEST_CHECK(bytes_equal(actual_tlv, actual_tlv_size, tlv, tlv_size));

    ASN1_TEST_CHECK(asn1_node_tag_class(node) == tag_class);
    ASN1_TEST_CHECK(asn1_node_tag_number(node) == tag_number);
    ASN1_TEST_CHECK(asn1_node_encoding_form(node) ==
                    (constructed ? ASN1_FORM_CONSTRUCTED
                                 : ASN1_FORM_PRIMITIVE));
    ASN1_TEST_CHECK(asn1_node_child_count(node) == 0);
    ASN1_TEST_CHECK(asn1_node_child_at(node, 0) == NULL);

    const uint8_t *content = NULL;
    size_t actual_content = 0;
    ASN1_TEST_CHECK(asn1_node_content(node, &content, &actual_content) ==
                    ASN1_OK);
    ASN1_TEST_CHECK(actual_content == content_size);
    if (content_size > 0) {
        ASN1_TEST_CHECK(content != NULL);
    }
    return 0;
}

/* 失败后读取上下文错误模型，校验错误码与 offset。 */
static int check_error(asn1_ctx_t *ctx, asn1_err_t expected_code,
                       size_t expected_offset, int has_offset)
{
    asn1_error_info_t info;
    memset(&info, 0, sizeof(info));
    info.struct_size = sizeof(info);
    ASN1_TEST_CHECK(asn1_ctx_get_error(ctx, &info) == ASN1_OK);
    ASN1_TEST_CHECK(info.code == expected_code);
    if (has_offset) {
        ASN1_TEST_CHECK(info.offset == expected_offset);
    }
    return 0;
}

/* ---------- 用例 ---------- */

int main(void)
{
    asn1_ctx_config_t config;
    asn1_ctx_config_init(&config);
    asn1_ctx_t *ctx = NULL;
    ASN1_TEST_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_OK);

    static const uint8_t kNullTlv[2] = {0x05, 0x00};
    static const uint8_t kSeqTlv[5] = {0x30, 0x03, 0x02, 0x01, 0x05};
    static const uint8_t kContextTlv[6] = {0xA1, 0x04, 0x04, 0x02, 0xAA, 0xBB};

    /* ===== 1. 能力位与公共入口一致性 ===== */
    {
        ASN1_TEST_CHECK(asn1_has_capability(ASN1_CAP_ANY_OPEN_TYPE) == 1);

        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(asn1_doc_create(ctx, &doc) == ASN1_OK);
        asn1_node_t *node = NULL;
        ASN1_TEST_CHECK(asn1_node_create_any(doc, NULL, kNullTlv,
                                             sizeof(kNullTlv), &node) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(node != NULL);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
        asn1_doc_destroy(doc);
    }

    /* ===== 2. 合法 TLV：基本 / 构造 / 上下文标签 ===== */
    {
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(asn1_doc_create(ctx, &doc) == ASN1_OK);
        asn1_node_t *node = NULL;
        ASN1_TEST_CHECK(asn1_node_create_any(doc, NULL, kNullTlv,
                                             sizeof(kNullTlv), &node) ==
                        ASN1_OK);
        const asn1_node_t *root = asn1_doc_root(doc);
        ASN1_TEST_CHECK(root == node);
        ASN1_TEST_CHECK(check_any_metadata(root, ASN1_TAG_UNIVERSAL, 5, 0,
                                           kNullTlv, sizeof(kNullTlv), 0) == 0);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
        asn1_doc_destroy(doc);
    }

    {
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(asn1_doc_create(ctx, &doc) == ASN1_OK);
        asn1_node_t *node = NULL;
        ASN1_TEST_CHECK(asn1_node_create_any(doc, NULL, kSeqTlv,
                                             sizeof(kSeqTlv), &node) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(check_any_metadata(asn1_doc_root(doc),
                                           ASN1_TAG_UNIVERSAL, 16, 1, kSeqTlv,
                                           sizeof(kSeqTlv), 3) == 0);
        asn1_doc_destroy(doc);
    }

    {
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(asn1_doc_create(ctx, &doc) == ASN1_OK);
        asn1_node_t *node = NULL;
        ASN1_TEST_CHECK(asn1_node_create_any(doc, NULL, kContextTlv,
                                             sizeof(kContextTlv), &node) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(check_any_metadata(asn1_doc_root(doc),
                                           ASN1_TAG_CONTEXT, 1, 1, kContextTlv,
                                           sizeof(kContextTlv), 4) == 0);
        asn1_doc_destroy(doc);
    }

    /* ===== 3. 调用方缓冲复制后可变 ===== */
    {
        uint8_t mutable_tlv[5] = {0x30, 0x03, 0x02, 0x01, 0x05};
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(asn1_doc_create(ctx, &doc) == ASN1_OK);
        asn1_node_t *node = NULL;
        ASN1_TEST_CHECK(asn1_node_create_any(doc, NULL, mutable_tlv,
                                             sizeof(mutable_tlv), &node) ==
                        ASN1_OK);
        mutable_tlv[4] = 0x07;
        size_t tlv_size = 0;
        const uint8_t *tlv = asn1_node_tlv(node, &tlv_size);
        ASN1_TEST_CHECK(tlv != NULL);
        ASN1_TEST_CHECK(tlv[4] == 0x05);
        asn1_doc_destroy(doc);
    }

    /* ===== 4. 嵌套在 SEQUENCE 与无 schema 往返 ===== */
    {
        static const uint8_t kExpected[7] = {0x30, 0x05, 0x30, 0x03,
                                             0x02, 0x01, 0x05};
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(asn1_doc_create(ctx, &doc) == ASN1_OK);
        asn1_node_t *root = NULL;
        ASN1_TEST_CHECK(asn1_node_create(doc, NULL, ASN1_TAG_UNIVERSAL, 16, 1,
                                         &root) == ASN1_OK);
        asn1_node_t *child = NULL;
        ASN1_TEST_CHECK(asn1_node_create_any(doc, root, kSeqTlv,
                                             sizeof(kSeqTlv), &child) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_child_count(root) == 1);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
        ASN1_TEST_CHECK(encode_compare(ctx, doc, NULL, kExpected,
                                       sizeof(kExpected)) == 0);
        asn1_doc_destroy(doc);
    }

    /* ===== 5. schema 感知往返：建树 → 编码 → 解码 → 再编码 ===== */
    {
        /* SEQUENCE { OID rsaEncryption, NULL }。 */
        static const uint8_t kExpected[15] = {
            0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
            0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00};
        asn1_schema_t *schema = make_algorithm_schema(ctx);
        ASN1_TEST_CHECK(schema != NULL);

        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(asn1_doc_create(ctx, &doc) == ASN1_OK);
        asn1_node_t *root = NULL;
        ASN1_TEST_CHECK(asn1_node_create(doc, NULL, ASN1_TAG_UNIVERSAL, 16, 1,
                                         &root) == ASN1_OK);
        asn1_node_t *oid = NULL;
        ASN1_TEST_CHECK(asn1_node_create(doc, root, ASN1_TAG_UNIVERSAL, 6, 0,
                                         &oid) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_oid(oid, "1.2.840.113549.1.1.1") ==
                        ASN1_OK);
        asn1_node_t *any_node = NULL;
        ASN1_TEST_CHECK(asn1_node_create_any(doc, root, kNullTlv,
                                             sizeof(kNullTlv), &any_node) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
        ASN1_TEST_CHECK(encode_compare(ctx, doc, schema, kExpected,
                                       sizeof(kExpected)) == 0);

        /* 解码同一份 DER 后再编码，逐字节一致。 */
        asn1_decode_options_t decode_options;
        asn1_decode_options_init(&decode_options);
        decode_options.encoding = ASN1_ENCODING_DER;
        asn1_doc_t *decoded = NULL;
        size_t consumed = 0;
        ASN1_TEST_CHECK(asn1_decode_buffer_with_schema(
                            ctx, kExpected, sizeof(kExpected), schema,
                            &decode_options, &decoded, &consumed) == ASN1_OK);
        ASN1_TEST_CHECK(consumed == sizeof(kExpected));
        const asn1_node_t *params =
            asn1_node_child_by_name(asn1_doc_root(decoded), "parameters");
        ASN1_TEST_CHECK(params != NULL);
        ASN1_TEST_CHECK(check_any_metadata(params, ASN1_TAG_UNIVERSAL, 5, 0,
                                           kNullTlv, sizeof(kNullTlv), 0) == 0);
        ASN1_TEST_CHECK(encode_compare(ctx, decoded, schema, kExpected,
                                       sizeof(kExpected)) == 0);

        asn1_doc_destroy(decoded);
        asn1_doc_destroy(doc);
        asn1_schema_destroy(schema);
    }

    /* ===== 6. 非规范 DER 的 ANY：创建接受，schema 编码拒绝 ===== */
    {
        /* INTEGER 5 带冗余前导零：TLV 结构完整，但不是规范 DER。 */
        static const uint8_t kNonCanonical[4] = {0x02, 0x02, 0x00, 0x05};
        static const uint8_t kRawRoundTrip[17] = {
            0x30, 0x0F, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
            0x0D, 0x01, 0x01, 0x01, 0x02, 0x02, 0x00, 0x05};
        asn1_schema_t *schema = make_algorithm_schema(ctx);
        ASN1_TEST_CHECK(schema != NULL);

        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(asn1_doc_create(ctx, &doc) == ASN1_OK);
        asn1_node_t *root = NULL;
        ASN1_TEST_CHECK(asn1_node_create(doc, NULL, ASN1_TAG_UNIVERSAL, 16, 1,
                                         &root) == ASN1_OK);
        asn1_node_t *oid = NULL;
        ASN1_TEST_CHECK(asn1_node_create(doc, root, ASN1_TAG_UNIVERSAL, 6, 0,
                                         &oid) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_oid(oid, "1.2.840.113549.1.1.1") ==
                        ASN1_OK);
        asn1_node_t *any_node = NULL;
        ASN1_TEST_CHECK(asn1_node_create_any(doc, root, kNonCanonical,
                                             sizeof(kNonCanonical),
                                             &any_node) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);

        /* schema 感知编码按 DER 校验保留 TLV，拒绝且不产出字节。 */
        asn1_encode_options_t options;
        asn1_encode_options_init(&options);
        options.schema = schema;
        asn1_buf_t buf;
        memset(&buf, 0, sizeof(buf));
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &options, &buf) ==
                        ASN1_E_NON_CANONICAL);
        ASN1_TEST_CHECK(buf.data == NULL);
        ASN1_TEST_CHECK(buf.size == 0);
        ASN1_TEST_CHECK(buf.capacity == 0);

        /* 无 schema 编码不做规范化，原样写出保留的 TLV。 */
        ASN1_TEST_CHECK(encode_compare(ctx, doc, NULL, kRawRoundTrip,
                                       sizeof(kRawRoundTrip)) == 0);

        asn1_doc_destroy(doc);
        asn1_schema_destroy(schema);
    }

    /* ===== 7. 资源上限透传：保留 TLV 超深时返回 DEPTH_LIMIT ===== */
    {
        asn1_ctx_config_t shallow;
        asn1_ctx_config_init(&shallow);
        shallow.max_depth = 2;
        asn1_ctx_t *shallow_ctx = NULL;
        ASN1_TEST_CHECK(asn1_ctx_create(&shallow, &shallow_ctx) == ASN1_OK);

        /* 三层 SEQUENCE 嵌套：解码深度超过 max_depth = 2。 */
        static const uint8_t kNested[9] = {0x30, 0x07, 0x30, 0x05, 0x30,
                                           0x03, 0x02, 0x01, 0x05};
        asn1_schema_t *schema = make_algorithm_schema(shallow_ctx);
        ASN1_TEST_CHECK(schema != NULL);

        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(asn1_doc_create(shallow_ctx, &doc) == ASN1_OK);
        asn1_node_t *root = NULL;
        ASN1_TEST_CHECK(asn1_node_create(doc, NULL, ASN1_TAG_UNIVERSAL, 16, 1,
                                         &root) == ASN1_OK);
        asn1_node_t *oid = NULL;
        ASN1_TEST_CHECK(asn1_node_create(doc, root, ASN1_TAG_UNIVERSAL, 6, 0,
                                         &oid) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_oid(oid, "1.2.840.113549.1.1.1") ==
                        ASN1_OK);
        asn1_node_t *any_node = NULL;
        ASN1_TEST_CHECK(asn1_node_create_any(doc, root, kNested,
                                             sizeof(kNested), &any_node) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);

        asn1_encode_options_t options;
        asn1_encode_options_init(&options);
        options.schema = schema;
        asn1_buf_t buf;
        memset(&buf, 0, sizeof(buf));
        ASN1_TEST_CHECK(asn1_encode_buffer(shallow_ctx, doc, &options, &buf) ==
                        ASN1_E_DEPTH_LIMIT);
        ASN1_TEST_CHECK(buf.data == NULL && buf.size == 0);
        asn1_doc_destroy(doc);
        asn1_schema_destroy(schema);
        asn1_ctx_destroy(shallow_ctx);
    }

    /* ===== 8. 负例：空输入、截断、尾随、不定长、畸形标签/长度 ===== */
    {
        static const uint8_t kTruncated[4] = {0x30, 0x03, 0x02, 0x01};
        static const uint8_t kTrailing[6] = {0x30, 0x03, 0x02, 0x01, 0x05, 0xFF};
        static const uint8_t kIndefinite[4] = {0x30, 0x80, 0x00, 0x00};
        static const uint8_t kHighTagIncomplete[1] = {0x1F};
        static const uint8_t kHighTagBadFirst[2] = {0x1F, 0x80};
        static const uint8_t kLengthTooLong[2] = {0x04, 0x89};

        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(asn1_doc_create(ctx, &doc) == ASN1_OK);
        asn1_node_t *node = NULL;

        asn1_ctx_clear_error(ctx);
        ASN1_TEST_CHECK(asn1_node_create_any(doc, NULL, NULL, 0, &node) ==
                        ASN1_E_INVALID_ARG);
        ASN1_TEST_CHECK(node == NULL);

        ASN1_TEST_CHECK(asn1_node_create_any(doc, NULL, kTruncated,
                                             sizeof(kTruncated), &node) ==
                        ASN1_E_TRUNCATED);
        ASN1_TEST_CHECK(check_error(ctx, ASN1_E_TRUNCATED, 4, 1) == 0);

        ASN1_TEST_CHECK(asn1_node_create_any(doc, NULL, kTrailing,
                                             sizeof(kTrailing), &node) ==
                        ASN1_E_TRAILING_DATA);
        ASN1_TEST_CHECK(check_error(ctx, ASN1_E_TRAILING_DATA, 5, 1) == 0);

        ASN1_TEST_CHECK(asn1_node_create_any(doc, NULL, kIndefinite,
                                             sizeof(kIndefinite), &node) ==
                        ASN1_E_INDEFINITE_NOT_ALLOWED);
        ASN1_TEST_CHECK(check_error(ctx, ASN1_E_INDEFINITE_NOT_ALLOWED, 1, 1) ==
                        0);

        ASN1_TEST_CHECK(asn1_node_create_any(doc, NULL, kHighTagIncomplete,
                                             sizeof(kHighTagIncomplete),
                                             &node) == ASN1_E_TRUNCATED);
        ASN1_TEST_CHECK(check_error(ctx, ASN1_E_TRUNCATED, 1, 1) == 0);

        ASN1_TEST_CHECK(asn1_node_create_any(doc, NULL, kHighTagBadFirst,
                                             sizeof(kHighTagBadFirst), &node) ==
                        ASN1_E_MALFORMED_TAG);
        ASN1_TEST_CHECK(check_error(ctx, ASN1_E_MALFORMED_TAG, 1, 1) == 0);

        ASN1_TEST_CHECK(asn1_node_create_any(doc, NULL, kLengthTooLong,
                                             sizeof(kLengthTooLong), &node) ==
                        ASN1_E_MALFORMED_LENGTH);

        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_E_INVALID_STATE);
        asn1_doc_destroy(doc);
    }

    /* ===== 9. ANY 不得挂子节点、不得设置内容 ===== */
    {
        asn1_doc_t *doc = NULL;
        ASN1_TEST_CHECK(asn1_doc_create(ctx, &doc) == ASN1_OK);
        asn1_node_t *any_node = NULL;
        ASN1_TEST_CHECK(asn1_node_create_any(doc, NULL, kSeqTlv,
                                             sizeof(kSeqTlv), &any_node) ==
                        ASN1_OK);
        asn1_node_t *child = NULL;
        ASN1_TEST_CHECK(asn1_node_create(doc, any_node, ASN1_TAG_UNIVERSAL, 2,
                                         0, &child) == ASN1_E_INVALID_STATE);
        ASN1_TEST_CHECK(child == NULL);
        ASN1_TEST_CHECK(asn1_node_set_content(any_node, kNullTlv,
                                              sizeof(kNullTlv)) ==
                        ASN1_E_INVALID_STATE);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
        asn1_doc_destroy(doc);
    }

    asn1_ctx_destroy(ctx);
    return 0;
}
