/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * ANY/开放类型：schema 注册与封存拒绝、描述表 kind = 6、节点语义
 * （原始 TLV 完整保留、child_count = 0、content 返回原始内容）、
 * 编码原样回写，以及真实证书 AlgorithmIdentifier.parameters 的实测。
 */
#include <asn1/asn1.h>

#include <stddef.h>
#include <string.h>

#include "../data/cert_ec_selfsigned.h"
#include "../data/cert_rsa_pss_selfsigned.h"
#include "../data/cert_rsa_selfsigned.h"
#include "check.h"
#include "schema_probe.h"

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

static asn1_type_desc_t make_any(const char *name)
{
    return make_type(name, ASN1_TYPE_KIND_ANY, ASN1_TAG_UNIVERSAL, 0,
                     ASN1_TAG_MODE_DEFAULT, 0);
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

static asn1_bound_t make_bound(int64_t value)
{
    asn1_bound_t bound;
    memset(&bound, 0, sizeof(bound));
    bound.struct_size = sizeof(bound);
    bound.value = value;
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

/*
 * 通过 schema-aware 解码把一段完整 TLV 解析为 ANY 根节点，验证节点语义
 * 并做无 schema 通用编码回写。expected_constructed 为 -1 表示不检查形态。
 * （原实现依赖内部探针构造 ANY 节点；现改走公共 API，解除共享库符号限制。）
 */
static int roundtrip_any(asn1_ctx_t *ctx, const uint8_t *tlv, size_t size,
                         int expected_constructed, size_t expected_content)
{
    asn1_schema_t *schema = NULL;
    ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                       &schema) == ASN1_OK);
    asn1_type_desc_t any_type = make_any("AnyRoot");
    uint32_t any_id = 0;
    ASN1_TEST_CHECK(asn1_schema_add_type(schema, &any_type, &any_id) ==
                    ASN1_OK);
    ASN1_TEST_CHECK(asn1_schema_set_root(schema, any_id) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

    asn1_decode_options_t options;
    asn1_decode_options_init(&options);
    options.encoding = ASN1_ENCODING_BER;

    asn1_doc_t *doc = NULL;
    size_t consumed = 0;
    ASN1_TEST_CHECK(asn1_decode_buffer_with_schema(
                        ctx, tlv, size, schema, &options, &doc, &consumed) ==
                    ASN1_OK);
    const asn1_node_t *node = asn1_doc_root(doc);
    ASN1_TEST_CHECK(node != NULL);

    /* 节点语义：ANY 不展开，TLV 完整保留。 */
    ASN1_TEST_CHECK(asn1_node_child_count(node) == 0);
    ASN1_TEST_CHECK(asn1_node_child_at(node, 0) == NULL);
    ASN1_TEST_CHECK(asn1_node_child_by_name(node, "x") == NULL);

    size_t tlv_size = 0;
    const uint8_t *raw = asn1_node_tlv(node, &tlv_size);
    ASN1_TEST_CHECK(raw != NULL);
    ASN1_TEST_CHECK(tlv_size == size);
    ASN1_TEST_CHECK(bytes_equal(raw, tlv_size, tlv, size));

    const uint8_t *content = NULL;
    size_t content_size = 0;
    ASN1_TEST_CHECK(asn1_node_content(node, &content, &content_size) ==
                    ASN1_OK);
    ASN1_TEST_CHECK(content_size == expected_content);
    if (expected_constructed >= 0) {
        ASN1_TEST_CHECK(asn1_node_encoding_form(node) ==
                        (expected_constructed ? ASN1_FORM_CONSTRUCTED
                                              : ASN1_FORM_PRIMITIVE));
    }

    asn1_buf_t buf;
    memset(&buf, 0, sizeof(buf));
    ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, &buf) == ASN1_OK);
    ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, tlv, size));
    ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
    asn1_doc_destroy(doc);
    asn1_schema_destroy(schema);
    return 0;
}

/* 取出真实证书签名 AlgorithmIdentifier 的 parameters 原始 TLV。 */
static const uint8_t *cert_parameters_tlv(asn1_doc_t *doc, size_t *out_size)
{
    const asn1_node_t *root = asn1_doc_root(doc);
    if (root == NULL) {
        return NULL;
    }
    const asn1_node_t *sig_alg = asn1_node_child_at(root, 1);
    if (sig_alg == NULL) {
        return NULL;
    }
    const asn1_node_t *params = asn1_node_child_at(sig_alg, 1);
    if (params == NULL) {
        return NULL;
    }
    return asn1_node_tlv(params, out_size);
}

/* ---------- 最小描述表（kind = 6） ---------- */

static void put_u16(uint8_t *data, size_t offset, uint32_t value)
{
    data[offset] = (uint8_t)(value & 0xFFu);
    data[offset + 1] = (uint8_t)((value >> 8) & 0xFFu);
}

static void put_u32(uint8_t *data, size_t offset, uint32_t value)
{
    for (int i = 0; i < 4; ++i) {
        data[offset + (size_t)i] = (uint8_t)((value >> (8 * i)) & 0xFFu);
    }
}

static void put_u64(uint8_t *data, size_t offset, uint64_t value)
{
    for (int i = 0; i < 8; ++i) {
        data[offset + (size_t)i] = (uint8_t)((value >> (8 * i)) & 0xFFu);
    }
}

static uint32_t crc32c(const uint8_t *data, size_t size)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < size; ++i) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; ++bit) {
            const uint32_t mask =
                (uint32_t)(-(int32_t)(crc & 1u)) & 0x82F63B78u;
            crc = (crc >> 1) ^ mask;
        }
    }
    return ~crc;
}

/* 构造只含一个 kind = 6 类型的描述表。 */
static void build_any_table(uint8_t *data, size_t size)
{
    memset(data, 0, size);

    static const uint8_t magic[8] = {0x41, 0x53, 0x4E, 0x31,
                                     0x53, 0x43, 0x48, 0x1A};
    memcpy(data, magic, sizeof(magic));
    put_u32(data, 8, 1u << 16);        /* format_version 1.0 */
    put_u32(data, 12, 100);            /* header_size */
    put_u32(data, 16, 0x01020304u);    /* endianness */
    put_u32(data, 20, 0);              /* module_tag_mode AUTOMATIC */
    put_u32(data, 24, 1);              /* flags: 校验和启用 */
    put_u32(data, 28, 1);              /* checksum_alg: CRC32C */
    put_u64(data, 32, (uint64_t)size);
    put_u32(data, 40, 100);            /* string_pool_offset */
    put_u32(data, 44, 9);              /* string_pool_size：含结尾 NUL */
    put_u32(data, 48, 112);            /* type_table_offset */
    put_u32(data, 52, 1);              /* type_count */
    /* 字段/约束/默认值表均为空。 */
    put_u32(data, 96, 1);              /* root_type_id */

    /* 字符串池：0x00 哨兵 + "AnyType" + NUL；109..111 为对齐填充。 */
    data[100] = 0x00;
    memcpy(data + 101, "AnyType", 7);
    data[108] = 0x00;

    /* 类型记录：name_off = 101，kind = 6，其余标签字段全 0。 */
    put_u32(data, 112, 101);
    put_u16(data, 116, 6);

    put_u32(data, 80, 0);
    put_u32(data, 80, crc32c(data, size));
}

/* ---------- 用例 ---------- */

int main(void)
{
    asn1_ctx_config_t config;
    asn1_ctx_config_init(&config);
    asn1_ctx_t *ctx = NULL;
    ASN1_TEST_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_OK);

    /* ===== 1. schema 运行时：ANY 注册与非法组合 ===== */
    {
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        asn1_type_desc_t any_type = make_any("AnyType");
        uint32_t any_id = 0;
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &any_type, &any_id) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(any_id == 1);

        asn1_test_type_info info;
        ASN1_TEST_CHECK(asn1_test_schema_type_info(schema, any_id, &info) == 1);
        ASN1_TEST_CHECK(info.kind == 6);
        ASN1_TEST_CHECK(info.tag_class == ASN1_TAG_UNIVERSAL);
        ASN1_TEST_CHECK(info.tag_number == 0);
        ASN1_TEST_CHECK(info.element_type_id == 0);
        ASN1_TEST_CHECK(info.field_count == 0);
        ASN1_TEST_CHECK(info.constraint_count == 0);

        /* ANY 不得挂字段。 */
        asn1_field_desc_t field = make_field("payload", any_id);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, any_id, &field) ==
                        ASN1_E_SCHEMA_FIELD);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);
        asn1_schema_destroy(schema);
    }

    {
        /* ANY 不得挂类型级约束。 */
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        asn1_type_desc_t any_type = make_any("AnyWithConstraint");
        asn1_constraint_t range = make_range(0, 10);
        any_type.constraints = &range;
        any_type.constraint_count = 1;
        uint32_t id = 0;
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &any_type, &id) ==
                        ASN1_E_SCHEMA_TYPE);
        asn1_schema_destroy(schema);
    }

    {
        /* ANY 只允许无包装（UNIVERSAL 0 + DEFAULT）或非 UNIVERSAL 的
           EXPLICIT 外层包装；IMPLICIT 与 CONTEXT DEFAULT 均非法。 */
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t id = 0;

        asn1_type_desc_t context_tag =
            make_type("AnyContext", ASN1_TYPE_KIND_ANY, ASN1_TAG_CONTEXT, 0,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &context_tag, &id) ==
                        ASN1_E_SCHEMA_TYPE);

        asn1_type_desc_t explicit_universal =
            make_type("AnyExplicitUniversal", ASN1_TYPE_KIND_ANY,
                      ASN1_TAG_UNIVERSAL, 0, ASN1_TAG_MODE_EXPLICIT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &explicit_universal, &id) ==
                        ASN1_E_SCHEMA_TYPE);

        asn1_type_desc_t implicit_tag =
            make_type("AnyImplicit", ASN1_TYPE_KIND_ANY, ASN1_TAG_CONTEXT, 0,
                      ASN1_TAG_MODE_IMPLICIT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &implicit_tag, &id) ==
                        ASN1_E_SCHEMA_TYPE);

        asn1_type_desc_t explicit_context =
            make_type("AnyExplicit", ASN1_TYPE_KIND_ANY, ASN1_TAG_CONTEXT, 1,
                      ASN1_TAG_MODE_EXPLICIT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &explicit_context, &id) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(id == 1);

        asn1_type_desc_t with_element =
            make_type("AnyOf", ASN1_TYPE_KIND_ANY, ASN1_TAG_UNIVERSAL, 0,
                      ASN1_TAG_MODE_DEFAULT, 1);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &with_element, &id) ==
                        ASN1_E_SCHEMA_TYPE);

        asn1_schema_destroy(schema);
    }

    /* ===== 1b. ANY OPTIONAL 的 seal 规则 ===== */
    {
        /* SEQUENCE { OID, ANY OPTIONAL } 可封存。 */
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t oid_id = 0;
        uint32_t any_id = 0;
        uint32_t seq_id = 0;
        asn1_type_desc_t oid_type =
            make_type("Oid", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 6,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &oid_type, &oid_id) ==
                        ASN1_OK);
        asn1_type_desc_t any_type = make_any("AnyType");
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &any_type, &any_id) ==
                        ASN1_OK);
        asn1_type_desc_t seq_type =
            make_type("AlgorithmIdentifier", ASN1_TYPE_KIND_SEQUENCE,
                      ASN1_TAG_UNIVERSAL, 16, ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &seq_type, &seq_id) ==
                        ASN1_OK);
        asn1_field_desc_t oid_field = make_field("algorithm", oid_id);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, seq_id, &oid_field) ==
                        ASN1_OK);
        asn1_field_desc_t any_field = make_field("parameters", any_id);
        any_field.flags = ASN1_FIELD_OPTIONAL;
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, seq_id, &any_field) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, seq_id) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        asn1_decode_options_t options;
        asn1_decode_options_init(&options);
        options.encoding = ASN1_ENCODING_BER;

        /* 带 NULL parameters。 */
        static const uint8_t kWithNull[7] = {0x30, 0x05, 0x06, 0x01,
                                             0x2A, 0x05, 0x00};
        asn1_doc_t *doc = NULL;
        size_t consumed = 0;
        ASN1_TEST_CHECK(asn1_decode_buffer_with_schema(
                            ctx, kWithNull, sizeof(kWithNull), schema,
                            &options, &doc, &consumed) == ASN1_OK);
        const asn1_node_t *root = asn1_doc_root(doc);
        ASN1_TEST_CHECK(root != NULL);
        ASN1_TEST_CHECK(asn1_node_child_count(root) == 2);
        const asn1_node_t *any_node =
            asn1_node_child_by_name(root, "parameters");
        ASN1_TEST_CHECK(any_node != NULL);
        ASN1_TEST_CHECK(asn1_node_child_count(any_node) == 0);
        size_t any_size = 0;
        const uint8_t *any_tlv = asn1_node_tlv(any_node, &any_size);
        ASN1_TEST_CHECK(any_size == 2);
        ASN1_TEST_CHECK(any_tlv != NULL);
        ASN1_TEST_CHECK(any_tlv[0] == 0x05 && any_tlv[1] == 0x00);
        asn1_doc_destroy(doc);

        /* 缺省 OPTIONAL ANY。 */
        static const uint8_t kWithoutAny[5] = {0x30, 0x03, 0x06, 0x01, 0x2A};
        ASN1_TEST_CHECK(asn1_decode_buffer_with_schema(
                            ctx, kWithoutAny, sizeof(kWithoutAny), schema,
                            &options, &doc, &consumed) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_child_count(asn1_doc_root(doc)) == 1);
        asn1_doc_destroy(doc);

        asn1_schema_destroy(schema);
    }

    {
        /* 末位 ANY 必选形态同样可封存与解码。 */
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t oid_id = 0;
        uint32_t any_id = 0;
        uint32_t seq_id = 0;
        asn1_type_desc_t oid_type =
            make_type("Oid", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 6,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &oid_type, &oid_id) ==
                        ASN1_OK);
        asn1_type_desc_t any_type = make_any("AnyType");
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &any_type, &any_id) ==
                        ASN1_OK);
        asn1_type_desc_t seq_type =
            make_type("MandatoryTail", ASN1_TYPE_KIND_SEQUENCE,
                      ASN1_TAG_UNIVERSAL, 16, ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &seq_type, &seq_id) ==
                        ASN1_OK);
        asn1_field_desc_t oid_field = make_field("algorithm", oid_id);
        asn1_field_desc_t any_field = make_field("parameters", any_id);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, seq_id, &oid_field) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, seq_id, &any_field) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, seq_id) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        asn1_decode_options_t options;
        asn1_decode_options_init(&options);
        options.encoding = ASN1_ENCODING_BER;
        static const uint8_t kWithNull[7] = {0x30, 0x05, 0x06, 0x01,
                                             0x2A, 0x05, 0x00};
        static const uint8_t kMissing[5] = {0x30, 0x03, 0x06, 0x01, 0x2A};
        asn1_doc_t *doc = NULL;
        size_t consumed = 0;
        ASN1_TEST_CHECK(asn1_decode_buffer_with_schema(
                            ctx, kWithNull, sizeof(kWithNull), schema,
                            &options, &doc, &consumed) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_child_count(asn1_doc_root(doc)) == 2);
        asn1_doc_destroy(doc);
        ASN1_TEST_CHECK(asn1_decode_buffer_with_schema(
                            ctx, kMissing, sizeof(kMissing), schema, &options,
                            &doc, &consumed) == ASN1_E_SCHEMA_FIELD);
        asn1_schema_destroy(schema);
    }

    {
        /* 非末位 DEFAULT-ANY 与非空 SET 中的 DEFAULT-ANY 均被拒。 */
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t oid_id = 0;
        uint32_t any_id = 0;
        uint32_t seq_id = 0;
        uint32_t set_id = 0;
        asn1_type_desc_t oid_type =
            make_type("Oid", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 6,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &oid_type, &oid_id) ==
                        ASN1_OK);
        asn1_type_desc_t any_type = make_any("AnyType");
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &any_type, &any_id) ==
                        ASN1_OK);
        asn1_type_desc_t seq_type =
            make_type("BadSequence", ASN1_TYPE_KIND_SEQUENCE,
                      ASN1_TAG_UNIVERSAL, 16, ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &seq_type, &seq_id) ==
                        ASN1_OK);
        asn1_field_desc_t any_field = make_field("anyFirst", any_id);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, seq_id, &any_field) ==
                        ASN1_OK);
        asn1_field_desc_t oid_field = make_field("oidLater", oid_id);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, seq_id, &oid_field) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_E_SCHEMA_TYPE);

        asn1_schema_destroy(schema);
    }

    {
        /* SET 依赖标签消歧，不允许 DEFAULT-ANY。 */
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t any_id = 0;
        uint32_t set_id = 0;
        asn1_type_desc_t any_type = make_any("AnyType");
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &any_type, &any_id) ==
                        ASN1_OK);
        asn1_type_desc_t set_type =
            make_type("BadSet", ASN1_TYPE_KIND_SET, ASN1_TAG_UNIVERSAL, 17,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &set_type, &set_id) ==
                        ASN1_OK);
        asn1_field_desc_t any_field = make_field("anyValue", any_id);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, set_id, &any_field) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_E_SCHEMA_TYPE);
        asn1_schema_destroy(schema);
    }

    /* ===== 1c. EXPLICIT ANY：节点即外层包装，content 为内层原始 TLV ===== */
    {
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t oid_id = 0;
        uint32_t any_id = 0;
        uint32_t seq_id = 0;
        asn1_type_desc_t oid_type =
            make_type("Oid", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 6,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &oid_type, &oid_id) ==
                        ASN1_OK);
        asn1_type_desc_t any_type =
            make_type("ExplicitAny", ASN1_TYPE_KIND_ANY, ASN1_TAG_CONTEXT, 1,
                      ASN1_TAG_MODE_EXPLICIT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &any_type, &any_id) ==
                        ASN1_OK);
        asn1_type_desc_t seq_type =
            make_type("SecurityCategory", ASN1_TYPE_KIND_SEQUENCE,
                      ASN1_TAG_UNIVERSAL, 16, ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &seq_type, &seq_id) ==
                        ASN1_OK);
        asn1_field_desc_t oid_field = make_field("type", oid_id);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, seq_id, &oid_field) ==
                        ASN1_OK);
        asn1_field_desc_t any_field = make_field("value", any_id);
        any_field.flags = ASN1_FIELD_OPTIONAL;
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, seq_id, &any_field) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, seq_id) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kInnerSeq[5] = {0x30, 0x03, 0x02, 0x01, 0x05};
        static const uint8_t kOuterSeq[12] = {0x30, 0x0A, 0x06, 0x01, 0x2A,
                                             0xA1, 0x05, 0x30, 0x03,
                                             0x02, 0x01, 0x05};
        static const uint8_t kInnerOctets[4] = {0x04, 0x02, 0xAA, 0xBB};
        static const uint8_t kOuterOctets[11] = {0x30, 0x09, 0x06, 0x01, 0x2A,
                                                0xA1, 0x04, 0x04, 0x02,
                                                0xAA, 0xBB};
        static const uint8_t kOuterContextZero[11] = {
            0x30, 0x09, 0x06, 0x01, 0x2A, 0xA0, 0x04, 0x04, 0x02, 0xAA, 0xBB};

        asn1_decode_options_t options;
        asn1_decode_options_init(&options);
        options.encoding = ASN1_ENCODING_BER;

        asn1_doc_t *doc = NULL;
        size_t consumed = 0;
        ASN1_TEST_CHECK(asn1_decode_buffer_with_schema(
                            ctx, kOuterSeq, sizeof(kOuterSeq), schema,
                            &options, &doc, &consumed) == ASN1_OK);
        const asn1_node_t *any_node =
            asn1_node_child_by_name(asn1_doc_root(doc), "value");
        ASN1_TEST_CHECK(any_node != NULL);
        ASN1_TEST_CHECK(asn1_node_child_count(any_node) == 0);
        size_t tlv_size = 0;
        const uint8_t *tlv = asn1_node_tlv(any_node, &tlv_size);
        ASN1_TEST_CHECK(tlv_size == 7);
        ASN1_TEST_CHECK(bytes_equal(tlv, tlv_size, kOuterSeq + 5, 7));
        const uint8_t *content = NULL;
        size_t content_size = 0;
        ASN1_TEST_CHECK(asn1_node_content(any_node, &content, &content_size) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(content_size == sizeof(kInnerSeq));
        ASN1_TEST_CHECK(bytes_equal(content, content_size, kInnerSeq,
                                    sizeof(kInnerSeq)));
        asn1_doc_destroy(doc);

        ASN1_TEST_CHECK(asn1_decode_buffer_with_schema(
                            ctx, kOuterOctets, sizeof(kOuterOctets), schema,
                            &options, &doc, &consumed) == ASN1_OK);
        any_node = asn1_node_child_by_name(asn1_doc_root(doc), "value");
        ASN1_TEST_CHECK(any_node != NULL);
        tlv = asn1_node_tlv(any_node, &tlv_size);
        ASN1_TEST_CHECK(tlv_size == 6);
        ASN1_TEST_CHECK(bytes_equal(tlv, tlv_size, kOuterOctets + 5, 6));
        ASN1_TEST_CHECK(asn1_node_content(any_node, &content, &content_size) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(content_size == sizeof(kInnerOctets));
        ASN1_TEST_CHECK(bytes_equal(content, content_size, kInnerOctets,
                                    sizeof(kInnerOctets)));
        asn1_doc_destroy(doc);

        /* 描述表路径：kind = 6 + EXPLICIT + CONTEXT 0 也能注册。 */
        asn1_schema_destroy(schema);
        asn1_schema_t *zero_schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &zero_schema) == ASN1_OK);
        uint32_t zero_any = 0;
        uint32_t zero_seq = 0;
        asn1_type_desc_t zero_type =
            make_type("ExplicitAnyZero", ASN1_TYPE_KIND_ANY,
                      ASN1_TAG_CONTEXT, 0, ASN1_TAG_MODE_EXPLICIT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(zero_schema, &zero_type,
                                             &zero_any) == ASN1_OK);
        asn1_type_desc_t zero_seq_type =
            make_type("OtherName", ASN1_TYPE_KIND_SEQUENCE,
                      ASN1_TAG_UNIVERSAL, 16, ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(zero_schema, &zero_seq_type,
                                             &zero_seq) == ASN1_OK);
        uint32_t zero_oid = 0;
        asn1_type_desc_t zero_oid_type =
            make_type("Oid", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL, 6,
                      ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(zero_schema, &zero_oid_type,
                                             &zero_oid) == ASN1_OK);
        asn1_field_desc_t oid_zero_field = make_field("type-id", zero_oid);
        ASN1_TEST_CHECK(asn1_schema_add_field(zero_schema, zero_seq,
                                              &oid_zero_field) == ASN1_OK);
        asn1_field_desc_t any_zero_field = make_field("value", zero_any);
        ASN1_TEST_CHECK(asn1_schema_add_field(zero_schema, zero_seq,
                                              &any_zero_field) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(zero_schema, zero_seq) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(zero_schema) == ASN1_OK);
        asn1_err_t zero_rc = asn1_decode_buffer_with_schema(
                            ctx, kOuterContextZero, sizeof(kOuterContextZero),
                            zero_schema, &options, &doc, &consumed);
        ASN1_TEST_CHECK(zero_rc == ASN1_OK);
        any_node = asn1_node_child_by_name(asn1_doc_root(doc), "value");
        ASN1_TEST_CHECK(any_node != NULL);
        tlv = asn1_node_tlv(any_node, &tlv_size);
        ASN1_TEST_CHECK(tlv_size == 6);
        ASN1_TEST_CHECK(bytes_equal(tlv, tlv_size, kOuterContextZero + 5, 6));
        asn1_doc_destroy(doc);
        asn1_schema_destroy(zero_schema);
    }

    /* ===== 1d. SET OF ANY：注册、封存与异构解码 ===== */
    {
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t any_id = 0;
        uint32_t set_of_id = 0;
        asn1_type_desc_t any_type = make_any("AttributeValue");
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &any_type, &any_id) ==
                        ASN1_OK);
        asn1_type_desc_t set_of_type =
            make_type("AttributeSet", ASN1_TYPE_KIND_SET_OF,
                      ASN1_TAG_UNIVERSAL, 17, ASN1_TAG_MODE_DEFAULT, any_id);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &set_of_type,
                                             &set_of_id) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, set_of_id) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kSetOfAny[13] = {
            0x31, 0x0B, 0x05, 0x00, 0x02, 0x01, 0x05, 0x04, 0x02,
            0xAA, 0xBB, 0x30, 0x00};
        asn1_decode_options_t options;
        asn1_decode_options_init(&options);
        options.encoding = ASN1_ENCODING_BER;
        asn1_doc_t *doc = NULL;
        size_t consumed = 0;
        ASN1_TEST_CHECK(asn1_decode_buffer_with_schema(
                            ctx, kSetOfAny, sizeof(kSetOfAny), schema, &options,
                            &doc, &consumed) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_child_count(asn1_doc_root(doc)) == 4);
        const asn1_node_t *element = asn1_node_child_at(asn1_doc_root(doc), 0);
        ASN1_TEST_CHECK(element != NULL);
        ASN1_TEST_CHECK(asn1_node_child_count(element) == 0);
        asn1_doc_destroy(doc);
        asn1_schema_destroy(schema);
    }


    /* ===== 2. 描述表 kind = 6 ===== */
    {
        uint8_t table_bytes[160];
        build_any_table(table_bytes, sizeof(table_bytes));

        asn1_schema_table_t table;
        memset(&table, 0, sizeof(table));
        table.struct_size = sizeof(table);
        table.data = table_bytes;
        table.size = sizeof(table_bytes);
        table.format_version = 1u << 16;

        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_load(ctx, &table, &schema) == ASN1_OK);
        asn1_test_type_info info;
        ASN1_TEST_CHECK(asn1_test_schema_type_info(schema, 1, &info) == 1);
        ASN1_TEST_CHECK(info.kind == 6);
        ASN1_TEST_CHECK(info.tag_number == 0);
        ASN1_TEST_CHECK(info.element_type_id == 0);
        asn1_schema_destroy(schema);
    }

    /* ===== 3. ANY 节点语义与编码回写 ===== */
    {
        static const uint8_t kNullTlv[2] = {0x05, 0x00};
        ASN1_TEST_CHECK(roundtrip_any(ctx, kNullTlv, sizeof(kNullTlv), 0, 0) ==
                        0);

        static const uint8_t kConstructedTlv[5] = {0x30, 0x03, 0x02, 0x01,
                                                   0x05};
        ASN1_TEST_CHECK(roundtrip_any(ctx, kConstructedTlv,
                                      sizeof(kConstructedTlv), 1, 3) == 0);

        /* 未知 OID 的任意 TLV：OID 1.2.3.4 与一段 OCTET STRING。 */
        static const uint8_t kUnknownOidTlv[10] = {
            0x30, 0x08, 0x06, 0x03, 0x2A, 0x03, 0x04, 0x04, 0x01, 0x00};
        ASN1_TEST_CHECK(roundtrip_any(ctx, kUnknownOidTlv,
                                      sizeof(kUnknownOidTlv), 1, 8) == 0);

        /* 无 schema 的通用编码路径：BER 不定长原始 TLV 按原样保留与回写。
           schema 感知 DER 编码会对此类源返回 ASN1_E_NON_CANONICAL。 */
        static const uint8_t kIndefiniteExact[7] = {0x30, 0x80, 0x02, 0x01,
                                                    0x05, 0x00, 0x00};
        ASN1_TEST_CHECK(roundtrip_any(ctx, kIndefiniteExact,
                                      sizeof(kIndefiniteExact), 1, 3) == 0);

        /* 注释中的承诺落到断言：BER 不定长保留 TLV 在 schema 感知 DER
           编码时返回 NON_CANONICAL，且不产出字节。 */
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        asn1_type_desc_t any_type = make_any("AnyRoot");
        uint32_t any_id = 0;
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &any_type, &any_id) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, any_id) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        asn1_decode_options_t decode_options;
        asn1_decode_options_init(&decode_options);
        decode_options.encoding = ASN1_ENCODING_BER;
        asn1_doc_t *doc = NULL;
        size_t consumed = 0;
        ASN1_TEST_CHECK(asn1_decode_buffer_with_schema(
                            ctx, kIndefiniteExact, sizeof(kIndefiniteExact),
                            schema, &decode_options, &doc, &consumed) ==
                        ASN1_OK);

        asn1_encode_options_t encode_options;
        asn1_encode_options_init(&encode_options);
        encode_options.schema = schema;
        asn1_buf_t buf;
        memset(&buf, 0, sizeof(buf));
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &encode_options, &buf) ==
                        ASN1_E_NON_CANONICAL);
        ASN1_TEST_CHECK(buf.data == NULL && buf.size == 0);
        asn1_doc_destroy(doc);
        asn1_schema_destroy(schema);
    }

    /* ===== 4. ANY 作为构造父节点的子节点（schema-aware 等价用例）===== */
    {
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        uint32_t any_id = 0;
        uint32_t seq_id = 0;
        asn1_type_desc_t any_type = make_any("Value");
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &any_type, &any_id) ==
                        ASN1_OK);
        asn1_type_desc_t seq_type =
            make_type("Wrapper", ASN1_TYPE_KIND_SEQUENCE, ASN1_TAG_UNIVERSAL,
                      16, ASN1_TAG_MODE_DEFAULT, 0);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &seq_type, &seq_id) ==
                        ASN1_OK);
        asn1_field_desc_t value_field = make_field("value", any_id);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, seq_id, &value_field) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, seq_id) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        static const uint8_t kSeqNull[4] = {0x30, 0x02, 0x05, 0x00};
        asn1_decode_options_t options;
        asn1_decode_options_init(&options);
        options.encoding = ASN1_ENCODING_BER;
        asn1_doc_t *doc = NULL;
        size_t consumed = 0;
        ASN1_TEST_CHECK(asn1_decode_buffer_with_schema(
                            ctx, kSeqNull, sizeof(kSeqNull), schema, &options,
                            &doc, &consumed) == ASN1_OK);
        const asn1_node_t *root = asn1_doc_root(doc);
        ASN1_TEST_CHECK(root != NULL);
        ASN1_TEST_CHECK(asn1_node_child_count(root) == 1);
        const asn1_node_t *any_node = asn1_node_child_by_name(root, "value");
        ASN1_TEST_CHECK(any_node != NULL);
        ASN1_TEST_CHECK(asn1_node_child_count(any_node) == 0);

        asn1_buf_t buf;
        memset(&buf, 0, sizeof(buf));
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, kSeqNull,
                                    sizeof(kSeqNull)));
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        asn1_doc_destroy(doc);
        asn1_schema_destroy(schema);
    }

    /* ===== 5. 真实证书 AlgorithmIdentifier.parameters ===== */
    {
        asn1_decode_options_t options;
        asn1_decode_options_init(&options);
        options.encoding = ASN1_ENCODING_BER;

        /* RSA：parameters = NULL (05 00)。 */
        asn1_doc_t *doc = NULL;
        size_t consumed = 0;
        ASN1_TEST_CHECK(asn1_decode_buffer(ctx, kCertRsaSelfsigned,
                                           kCertRsaSelfsignedSize, &options,
                                           &doc, &consumed) == ASN1_OK);
        size_t param_size = 0;
        const uint8_t *param = cert_parameters_tlv(doc, &param_size);
        ASN1_TEST_CHECK(param != NULL);
        ASN1_TEST_CHECK(param_size == 2);
        ASN1_TEST_CHECK(param[0] == 0x05 && param[1] == 0x00);
        ASN1_TEST_CHECK(roundtrip_any(ctx, param, param_size, 0, 0) == 0);
        asn1_doc_destroy(doc);

        /* RSA-PSS：parameters = SEQUENCE。 */
        doc = NULL;
        consumed = 0;
        ASN1_TEST_CHECK(asn1_decode_buffer(ctx, kCertRsaPssSelfsigned,
                                           kCertRsaPssSelfsignedSize,
                                           &options, &doc, &consumed) ==
                        ASN1_OK);
        param = cert_parameters_tlv(doc, &param_size);
        ASN1_TEST_CHECK(param != NULL);
        ASN1_TEST_CHECK(param_size > 2);
        ASN1_TEST_CHECK(param[0] == 0x30);
        ASN1_TEST_CHECK(roundtrip_any(ctx, param, param_size, 1,
                                      param_size - 2) == 0);
        asn1_doc_destroy(doc);

        /* EC：ecdsa-with-SHA256 的 AlgorithmIdentifier 参数缺省（无子节点）。 */
        doc = NULL;
        consumed = 0;
        ASN1_TEST_CHECK(asn1_decode_buffer(ctx, kCertEcSelfsigned,
                                           kCertEcSelfsignedSize, &options,
                                           &doc, &consumed) == ASN1_OK);
        param = cert_parameters_tlv(doc, &param_size);
        ASN1_TEST_CHECK(param == NULL);
        asn1_doc_destroy(doc);
    }

    asn1_ctx_destroy(ctx);
    return 0;
}
