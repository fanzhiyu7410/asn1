/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * schema 描述表加载路径：手写 uint8_t[] 夹具、CRC32C、结构校验以及
 * 与运行时注册路径的等价性。
 */

#include <asn1/asn1.h>

#include <stdio.h>
#include <string.h>

#include "check.h"
#include "schema_compare.h"
#include "schema_probe.h"

/* 夹具的总布局（全部为绝对文件偏移）。 */
#define TABLE_SIZE 976u
#define OFF_STRING_POOL 104u
#define SIZE_STRING_POOL 104u
#define OFF_TYPE_TABLE 216u
#define COUNT_TYPE 7u
#define OFF_FIELD_TABLE 552u
#define COUNT_FIELD 6u
#define OFF_CONSTRAINT_TABLE 744u
#define COUNT_CONSTRAINT 4u
#define OFF_DEFAULT_TABLE 936u
#define COUNT_DEFAULT 1u
#define OFF_ENUM_ARRAY 944u
#define OFF_DEFAULT_BYTES 968u
#define SIZE_DEFAULT_BYTES 5u

/* 字符串池内的绝对偏移。 */
#define STR_INT_TYPE 105u
#define STR_TEXT_TYPE 113u
#define STR_BOOL_TYPE 122u
#define STR_SEQ_TYPE 131u
#define STR_SET_TYPE 139u
#define STR_SEQ_OF_TYPE 147u
#define STR_CHOICE_TYPE 157u
#define STR_FIELD_VALUE 168u
#define STR_FIELD_LABEL 174u
#define STR_FIELD_A 180u
#define STR_FIELD_B 182u
#define STR_FIELD_INT 184u
#define STR_FIELD_TEXT 194u
#define STR_DEC_LEADING_ZERO 205u

static const uint8_t kMagic[8] = {0x41, 0x53, 0x4E, 0x31,
                                  0x53, 0x43, 0x48, 0x1A};
static const uint8_t kDefaultText[5] = {0x0C, 0x03, 'a', 'b', 'c'};

/* ===== 小端写入辅助（夹具侧独立实现，不依赖库内工具） ===== */

static void put_u16(uint8_t *buf, size_t off, uint16_t value)
{
    buf[off] = (uint8_t)(value & 0xFFu);
    buf[off + 1] = (uint8_t)((value >> 8) & 0xFFu);
}

static uint32_t get_u32(const uint8_t *buf, size_t off)
{
    return (uint32_t)buf[off] | ((uint32_t)buf[off + 1] << 8) |
           ((uint32_t)buf[off + 2] << 16) |
           ((uint32_t)buf[off + 3] << 24);
}

static void put_u32(uint8_t *buf, size_t off, uint32_t value)
{
    buf[off] = (uint8_t)(value & 0xFFu);
    buf[off + 1] = (uint8_t)((value >> 8) & 0xFFu);
    buf[off + 2] = (uint8_t)((value >> 16) & 0xFFu);
    buf[off + 3] = (uint8_t)((value >> 24) & 0xFFu);
}

static void put_u64(uint8_t *buf, size_t off, uint64_t value)
{
    put_u32(buf, off, (uint32_t)(value & 0xFFFFFFFFu));
    put_u32(buf, off + 4, (uint32_t)((value >> 32) & 0xFFFFFFFFu));
}

static void put_i64(uint8_t *buf, size_t off, int64_t value)
{
    uint64_t raw;
    if (value >= 0) {
        raw = (uint64_t)value;
    } else {
        raw = UINT64_MAX - (uint64_t)(-(value + 1));
    }
    put_u64(buf, off, raw);
}

/* 测试侧独立 CRC32C（Castagnoli，反射实现）。 */
static uint32_t crc32c_zeroed(const uint8_t *data, size_t size,
                              size_t zero_off, size_t zero_len)
{
    uint32_t crc = 0xFFFFFFFFu;
    size_t i;
    for (i = 0; i < size; ++i) {
        uint32_t byte = (uint32_t)data[i];
        uint32_t bit;
        if (i >= zero_off && i < zero_off + zero_len) {
            byte = 0;
        }
        crc ^= byte;
        for (bit = 0; bit < 8; ++bit) {
            uint32_t mask = (uint32_t)(0u - (crc & 1u));
            crc = (crc >> 1) ^ (0x82F63B78u & mask);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

/* ===== 夹具构造 ===== */

static void put_type(uint8_t *buf, uint32_t index, uint32_t name_off,
                     uint16_t kind, uint8_t tag_mode, uint8_t flags,
                     uint8_t tag_class, uint32_t tag_number,
                     uint32_t element_type_id, uint32_t field_start,
                     uint32_t field_count, uint32_t constraint_start,
                     uint32_t constraint_count)
{
    uint8_t *rec = buf + OFF_TYPE_TABLE + (size_t)index * 48u;
    memset(rec, 0, 48u);
    put_u32(rec, 0, name_off);
    put_u16(rec, 4, kind);
    rec[6] = tag_mode;
    rec[7] = flags;
    rec[8] = tag_class;
    put_u32(rec, 12, tag_number);
    put_u32(rec, 16, element_type_id);
    put_u32(rec, 20, field_start);
    put_u32(rec, 24, field_count);
    put_u32(rec, 28, constraint_start);
    put_u32(rec, 32, constraint_count);
}

static void put_field(uint8_t *buf, uint32_t index, uint32_t name_off,
                      uint32_t type_id, uint16_t flags, uint32_t default_index,
                      uint32_t constraint_start, uint32_t constraint_count)
{
    uint8_t *rec = buf + OFF_FIELD_TABLE + (size_t)index * 32u;
    memset(rec, 0, 32u);
    put_u32(rec, 0, name_off);
    put_u32(rec, 4, type_id);
    put_u16(rec, 8, flags);
    put_u32(rec, 12, default_index);
    put_u32(rec, 16, constraint_start);
    put_u32(rec, 20, constraint_count);
}

static void put_constraint(uint8_t *buf, uint32_t index, uint16_t kind,
                           uint16_t flags, uint32_t enum_off,
                           uint32_t enum_count, uint32_t lower_off,
                           uint32_t lower_size, uint32_t upper_off,
                           uint32_t upper_size, int64_t lower_value,
                           int64_t upper_value)
{
    uint8_t *rec = buf + OFF_CONSTRAINT_TABLE + (size_t)index * 48u;
    memset(rec, 0, 48u);
    put_u16(rec, 0, kind);
    put_u16(rec, 2, flags);
    put_u32(rec, 4, enum_off);
    put_u32(rec, 8, enum_count);
    put_u32(rec, 12, lower_off);
    put_u32(rec, 16, lower_size);
    put_u32(rec, 20, upper_off);
    put_u32(rec, 24, upper_size);
    put_i64(rec, 28, lower_value);
    put_i64(rec, 36, upper_value);
}

static void refresh_checksum(uint8_t *buf)
{
    uint32_t crc;
    put_u32(buf, 80, 0);
    crc = crc32c_zeroed(buf, TABLE_SIZE, 80, 4);
    put_u32(buf, 80, crc);
}

static void build_base_table(uint8_t *buf)
{
    memset(buf, 0, TABLE_SIZE);
    memcpy(buf, kMagic, 8);
    put_u32(buf, 8, 0x00010000u);   /* format_version 1.0 */
    put_u32(buf, 12, 100);          /* header_size：基线含 root_type_id */
    put_u32(buf, 16, 0x01020304u);  /* endianness */
    put_u32(buf, 20, 2);            /* module_tag_mode = IMPLICIT */
    put_u32(buf, 24, 1);            /* flags：位 0 必须为 1 */
    put_u32(buf, 28, 1);            /* checksum_alg = CRC32C */
    put_u64(buf, 32, TABLE_SIZE);   /* total_size */
    put_u32(buf, 40, OFF_STRING_POOL);
    put_u32(buf, 44, SIZE_STRING_POOL);
    put_u32(buf, 48, OFF_TYPE_TABLE);
    put_u32(buf, 52, COUNT_TYPE);
    put_u32(buf, 56, OFF_FIELD_TABLE);
    put_u32(buf, 60, COUNT_FIELD);
    put_u32(buf, 64, OFF_CONSTRAINT_TABLE);
    put_u32(buf, 68, COUNT_CONSTRAINT);
    put_u32(buf, 72, OFF_DEFAULT_TABLE);
    put_u32(buf, 76, COUNT_DEFAULT);
    put_u32(buf, 96, 4);            /* root_type_id = SeqType */

    /* 字符串池：首字节为 0 哨兵。 */
    buf[OFF_STRING_POOL] = 0;
    memcpy(buf + STR_INT_TYPE, "IntType", 8);
    memcpy(buf + STR_TEXT_TYPE, "TextType", 9);
    memcpy(buf + STR_BOOL_TYPE, "BoolType", 9);
    memcpy(buf + STR_SEQ_TYPE, "SeqType", 8);
    memcpy(buf + STR_SET_TYPE, "SetType", 8);
    memcpy(buf + STR_SEQ_OF_TYPE, "SeqOfType", 10);
    memcpy(buf + STR_CHOICE_TYPE, "ChoiceType", 11);
    memcpy(buf + STR_FIELD_VALUE, "value", 6);
    memcpy(buf + STR_FIELD_LABEL, "label", 6);
    memcpy(buf + STR_FIELD_A, "a", 2);
    memcpy(buf + STR_FIELD_B, "b", 2);
    memcpy(buf + STR_FIELD_INT, "intBranch", 10);
    memcpy(buf + STR_FIELD_TEXT, "textBranch", 11);
    memcpy(buf + STR_DEC_LEADING_ZERO, "01", 3);

    /* 类型表（kind：0 SIMPLE、1 SEQUENCE、2 SET、3 CHOICE、4 SEQUENCE_OF）。 */
    put_type(buf, 0, STR_INT_TYPE, 0, 0, 0, 0, 2, 0, 0, 0, 0, 1);
    put_type(buf, 1, STR_TEXT_TYPE, 0, 0, 0, 0, 12, 0, 0, 0, 1, 1);
    put_type(buf, 2, STR_BOOL_TYPE, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0);
    put_type(buf, 3, STR_SEQ_TYPE, 1, 0, 1, 0, 0, 0, 0, 2, 0, 0);
    put_type(buf, 4, STR_SET_TYPE, 2, 0, 0, 0, 0, 0, 2, 2, 0, 0);
    put_type(buf, 5, STR_SEQ_OF_TYPE, 4, 0, 0, 0, 0, 1, 0, 0, 0, 0);
    put_type(buf, 6, STR_CHOICE_TYPE, 3, 0, 0, 0, 0, 0, 4, 2, 0, 0);

    /* 字段表：SeqType(value,label)、SetType(a,b)、ChoiceType(intBranch,textBranch)。 */
    put_field(buf, 0, STR_FIELD_VALUE, 1, 0, 0, 2, 1);
    put_field(buf, 1, STR_FIELD_LABEL, 2, ASN1_FIELD_OPTIONAL,
              COUNT_DEFAULT, 0, 0);
    put_field(buf, 2, STR_FIELD_A, 1, 0, 0, 3, 1);
    put_field(buf, 3, STR_FIELD_B, 3, 0, 0, 0, 0);
    put_field(buf, 4, STR_FIELD_INT, 1, 0, 0, 0, 0);
    put_field(buf, 5, STR_FIELD_TEXT, 2, 0, 0, 0, 0);

    /* 约束表：RANGE、SIZE、ENUM、MAX。 */
    put_constraint(buf, 0, 0, 0, 0, 0, 0, 0, 0, 0, -128, 127);
    put_constraint(buf, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 64);
    put_constraint(buf, 2, 2, 0, OFF_ENUM_ARRAY, 3, 0, 0, 0, 0, 0, 0);
    put_constraint(buf, 3, 3, 0x0002u, 0, 0, 0, 0, 0, 0, 0, 0);

    /* 默认值表与内容。 */
    put_u32(buf, OFF_DEFAULT_TABLE, OFF_DEFAULT_BYTES);
    put_u32(buf, OFF_DEFAULT_TABLE + 4, SIZE_DEFAULT_BYTES);
    put_i64(buf, OFF_ENUM_ARRAY, 1);
    put_i64(buf, OFF_ENUM_ARRAY + 8, 2);
    put_i64(buf, OFF_ENUM_ARRAY + 16, 3);
    memcpy(buf + OFF_DEFAULT_BYTES, kDefaultText, SIZE_DEFAULT_BYTES);

    refresh_checksum(buf);
}

static asn1_schema_table_t make_table(const uint8_t *data, size_t size)
{
    asn1_schema_table_t table;
    memset(&table, 0, sizeof(table));
    table.struct_size = sizeof(table);
    table.data = data;
    table.size = size;
    table.format_version = 0x00010000u;
    return table;
}

static int expect_load_error(asn1_ctx_t *ctx, const uint8_t *data,
                             size_t size, asn1_err_t expected)
{
    asn1_schema_table_t table = make_table(data, size);
    asn1_schema_t *schema = (asn1_schema_t *)(void *)0x1;
    asn1_err_t rc = asn1_schema_load(ctx, &table, &schema);
    if (rc != expected || schema != NULL) {
        fprintf(stderr, "load error mismatch: got %d, expected %d\n",
                (int)rc, (int)expected);
        return 0;
    }
    return 1;
}

/* ===== 运行时注册路径：与夹具同构 ===== */

static asn1_type_desc_t make_type(const char *name, asn1_type_kind_t kind,
                                  asn1_tag_class_t tag_class,
                                  uint32_t tag_number,
                                  asn1_tag_mode_t tag_mode,
                                  uint32_t element_type_id)
{
    asn1_type_desc_t desc;
    memset(&desc, 0, sizeof(desc));
    desc.struct_size = sizeof(desc);
    desc.name = name;
    desc.kind = kind;
    desc.tag_class = tag_class;
    desc.tag_number = tag_number;
    desc.tag_mode = tag_mode;
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

static asn1_bound_t make_bound(int64_t value, int32_t unbounded)
{
    asn1_bound_t bound;
    memset(&bound, 0, sizeof(bound));
    bound.struct_size = sizeof(bound);
    bound.is_unbounded = unbounded;
    bound.value = value;
    return bound;
}

static asn1_constraint_t make_range(int64_t lower, int64_t upper)
{
    asn1_constraint_t c;
    memset(&c, 0, sizeof(c));
    c.struct_size = sizeof(c);
    c.kind = ASN1_CONSTRAINT_RANGE;
    c.lower = make_bound(lower, 0);
    c.upper = make_bound(upper, 0);
    return c;
}

static asn1_constraint_t make_size(int64_t lower, int64_t upper)
{
    asn1_constraint_t c;
    memset(&c, 0, sizeof(c));
    c.struct_size = sizeof(c);
    c.kind = ASN1_CONSTRAINT_SIZE;
    c.lower = make_bound(lower, 0);
    c.upper = make_bound(upper, 0);
    return c;
}

static asn1_constraint_t make_max(void)
{
    asn1_constraint_t c;
    memset(&c, 0, sizeof(c));
    c.struct_size = sizeof(c);
    c.kind = ASN1_CONSTRAINT_MAX;
    c.lower = make_bound(0, 0);
    c.upper = make_bound(0, 1);
    return c;
}

static int build_runtime_schema(asn1_ctx_t *ctx, asn1_schema_t **out_schema)
{
    static const int64_t kEnums[3] = {1, 2, 3};
    asn1_schema_t *schema = NULL;
    asn1_constraint_t range = make_range(-128, 127);
    asn1_constraint_t size = make_size(0, 64);
    asn1_constraint_t maxValue = make_max();
    asn1_constraint_t enumValue;
    asn1_type_desc_t desc;
    asn1_field_desc_t field;
    uint32_t id = 0;

    memset(&enumValue, 0, sizeof(enumValue));
    enumValue.struct_size = sizeof(enumValue);
    enumValue.kind = ASN1_CONSTRAINT_ENUM;
    enumValue.enum_values = kEnums;
    enumValue.enum_count = 3;

    if (asn1_schema_create(ctx, ASN1_TAG_MODE_IMPLICIT, &schema) != ASN1_OK) {
        return 0;
    }

    desc = make_type("IntType", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL,
                     2, ASN1_TAG_MODE_DEFAULT, 0);
    desc.constraints = &range;
    desc.constraint_count = 1;
    if (asn1_schema_add_type(schema, &desc, &id) != ASN1_OK) {
        return 0;
    }
    desc = make_type("TextType", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL,
                     12, ASN1_TAG_MODE_DEFAULT, 0);
    desc.constraints = &size;
    desc.constraint_count = 1;
    if (asn1_schema_add_type(schema, &desc, &id) != ASN1_OK) {
        return 0;
    }
    desc = make_type("BoolType", ASN1_TYPE_KIND_SIMPLE, ASN1_TAG_UNIVERSAL,
                     1, ASN1_TAG_MODE_DEFAULT, 0);
    if (asn1_schema_add_type(schema, &desc, &id) != ASN1_OK) {
        return 0;
    }
    desc = make_type("SeqType", ASN1_TYPE_KIND_SEQUENCE, ASN1_TAG_UNIVERSAL,
                     0, ASN1_TAG_MODE_DEFAULT, 0);
    desc.flags = ASN1_TYPE_EXTENSIBLE;
    if (asn1_schema_add_type(schema, &desc, &id) != ASN1_OK) {
        return 0;
    }
    desc = make_type("SetType", ASN1_TYPE_KIND_SET, ASN1_TAG_UNIVERSAL,
                     0, ASN1_TAG_MODE_DEFAULT, 0);
    if (asn1_schema_add_type(schema, &desc, &id) != ASN1_OK) {
        return 0;
    }
    desc = make_type("SeqOfType", ASN1_TYPE_KIND_SEQUENCE_OF,
                     ASN1_TAG_UNIVERSAL, 0, ASN1_TAG_MODE_DEFAULT, 1);
    if (asn1_schema_add_type(schema, &desc, &id) != ASN1_OK) {
        return 0;
    }
    desc = make_type("ChoiceType", ASN1_TYPE_KIND_CHOICE, ASN1_TAG_UNIVERSAL,
                     0, ASN1_TAG_MODE_DEFAULT, 0);
    if (asn1_schema_add_type(schema, &desc, &id) != ASN1_OK) {
        return 0;
    }

    field = make_field("value", 1);
    field.field_constraints = &enumValue;
    field.field_constraint_count = 1;
    if (asn1_schema_add_field(schema, 4, &field) != ASN1_OK) {
        return 0;
    }
    field = make_field("label", 2);
    field.flags = ASN1_FIELD_OPTIONAL;
    field.default_value = kDefaultText;
    field.default_value_size = SIZE_DEFAULT_BYTES;
    if (asn1_schema_add_field(schema, 4, &field) != ASN1_OK) {
        return 0;
    }
    field = make_field("a", 1);
    field.field_constraints = &maxValue;
    field.field_constraint_count = 1;
    if (asn1_schema_add_field(schema, 5, &field) != ASN1_OK) {
        return 0;
    }
    field = make_field("b", 3);
    if (asn1_schema_add_field(schema, 5, &field) != ASN1_OK) {
        return 0;
    }
    field = make_field("intBranch", 1);
    if (asn1_schema_add_field(schema, 7, &field) != ASN1_OK) {
        return 0;
    }
    field = make_field("textBranch", 2);
    if (asn1_schema_add_field(schema, 7, &field) != ASN1_OK) {
        return 0;
    }

    if (asn1_schema_set_root(schema, 4) != ASN1_OK) {
        return 0;
    }
    if (asn1_schema_seal(schema) != ASN1_OK) {
        return 0;
    }
    *out_schema = schema;
    return 1;
}

/* ===== 两条路径的等价比较（逐字段比较实现在 schema_compare.c） ===== */

static int expect_type(const asn1_schema_t *schema, uint32_t type_id,
                       const char *name, uint32_t kind, uint32_t tag_class,
                       uint32_t tag_number, uint32_t tag_mode,
                       uint32_t element_type_id, uint32_t flags,
                       uint32_t field_count, uint32_t constraint_count)
{
    asn1_test_type_info info;
    if (!asn1_test_schema_type_info(schema, type_id, &info)) {
        return 0;
    }
    return strcmp(info.name, name) == 0 && info.kind == kind &&
           info.tag_class == tag_class && info.tag_number == tag_number &&
           info.tag_mode == tag_mode &&
           info.element_type_id == element_type_id && info.flags == flags &&
           info.field_count == field_count &&
           info.constraint_count == constraint_count;
}

int main(void)
{
    static uint8_t base[TABLE_SIZE];
    static uint8_t work[TABLE_SIZE];
    asn1_ctx_config_t config;
    asn1_ctx_t *ctx = NULL;
    asn1_schema_table_t table;
    asn1_schema_t *loaded = NULL;
    asn1_schema_t *runtime = NULL;

    /* CRC32C 独立向量与校验和字段按 0 参与。 */
    {
        static const uint8_t check[9] = {'1', '2', '3', '4',
                                         '5', '6', '7', '8', '9'};
        ASN1_TEST_CHECK(crc32c_zeroed(check, 9, 0, 0) == 0xE3069283u);
    }

    build_base_table(base);
    ASN1_TEST_CHECK(crc32c_zeroed(base, TABLE_SIZE, 80, 4) ==
                    get_u32(base, 80));
    ASN1_TEST_CHECK(crc32c_zeroed(base, TABLE_SIZE, 80, 4) !=
                    crc32c_zeroed(base, TABLE_SIZE, 0, 0));

    asn1_ctx_config_init(&config);
    ASN1_TEST_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_OK);

    /* 合法表：全部结构校验通过并封存。 */
    table = make_table(base, TABLE_SIZE);
    ASN1_TEST_CHECK(asn1_schema_load(ctx, &table, &loaded) == ASN1_OK);
    ASN1_TEST_CHECK(loaded != NULL);
    ASN1_TEST_CHECK(asn1_test_schema_type_count(loaded) == COUNT_TYPE);
    ASN1_TEST_CHECK(asn1_test_schema_module_tag_mode(loaded) ==
                    ASN1_TAG_MODE_IMPLICIT);
    ASN1_TEST_CHECK(asn1_test_schema_root_type_id(loaded) == 4);
    ASN1_TEST_CHECK(asn1_test_schema_sealed(loaded) == 1);
    ASN1_TEST_CHECK(expect_type(loaded, 1, "IntType", ASN1_TYPE_KIND_SIMPLE,
                                ASN1_TAG_UNIVERSAL, 2, ASN1_TAG_MODE_DEFAULT,
                                0, 0, 0, 1));
    ASN1_TEST_CHECK(expect_type(loaded, 2, "TextType", ASN1_TYPE_KIND_SIMPLE,
                                ASN1_TAG_UNIVERSAL, 12,
                                ASN1_TAG_MODE_DEFAULT, 0, 0, 0, 1));
    ASN1_TEST_CHECK(expect_type(loaded, 3, "BoolType", ASN1_TYPE_KIND_SIMPLE,
                                ASN1_TAG_UNIVERSAL, 1, ASN1_TAG_MODE_DEFAULT,
                                0, 0, 0, 0));
    ASN1_TEST_CHECK(expect_type(loaded, 4, "SeqType", ASN1_TYPE_KIND_SEQUENCE,
                                ASN1_TAG_UNIVERSAL, 0, ASN1_TAG_MODE_DEFAULT,
                                0, ASN1_TYPE_EXTENSIBLE, 2, 0));
    ASN1_TEST_CHECK(expect_type(loaded, 5, "SetType", ASN1_TYPE_KIND_SET,
                                ASN1_TAG_UNIVERSAL, 0, ASN1_TAG_MODE_DEFAULT,
                                0, 0, 2, 0));
    ASN1_TEST_CHECK(expect_type(loaded, 6, "SeqOfType",
                                ASN1_TYPE_KIND_SEQUENCE_OF,
                                ASN1_TAG_UNIVERSAL, 0, ASN1_TAG_MODE_DEFAULT,
                                1, 0, 0, 0));
    ASN1_TEST_CHECK(expect_type(loaded, 7, "ChoiceType", ASN1_TYPE_KIND_CHOICE,
                                ASN1_TAG_UNIVERSAL, 0, ASN1_TAG_MODE_DEFAULT,
                                0, 0, 2, 0));

    /* 字段与默认值。 */
    {
        asn1_test_field_info info;
        const uint8_t *bytes;
        size_t size = 0;
        ASN1_TEST_CHECK(asn1_test_schema_field_info(loaded, 4, 0, &info) == 1);
        ASN1_TEST_CHECK(strcmp(info.name, "value") == 0);
        ASN1_TEST_CHECK(info.type_id == 1);
        ASN1_TEST_CHECK(info.flags == 0);
        ASN1_TEST_CHECK(info.default_size == 0);
        ASN1_TEST_CHECK(info.constraint_count == 1);
        ASN1_TEST_CHECK(asn1_test_schema_field_info(loaded, 4, 1, &info) == 1);
        ASN1_TEST_CHECK(strcmp(info.name, "label") == 0);
        ASN1_TEST_CHECK(info.type_id == 2);
        ASN1_TEST_CHECK(info.flags == ASN1_FIELD_OPTIONAL);
        ASN1_TEST_CHECK(info.default_size == SIZE_DEFAULT_BYTES);
        ASN1_TEST_CHECK(info.constraint_count == 0);
        bytes = asn1_test_schema_field_default(loaded, 4, 1, &size);
        ASN1_TEST_CHECK(bytes != NULL);
        ASN1_TEST_CHECK(size == SIZE_DEFAULT_BYTES);
        ASN1_TEST_CHECK(memcmp(bytes, kDefaultText, SIZE_DEFAULT_BYTES) == 0);
    }

    /* 约束值。 */
    {
        asn1_test_constraint_info info;
        ASN1_TEST_CHECK(asn1_test_schema_type_constraint(loaded, 1, 0,
                                                         &info) == 1);
        ASN1_TEST_CHECK(info.kind == ASN1_CONSTRAINT_RANGE);
        ASN1_TEST_CHECK(info.lower.value == -128);
        ASN1_TEST_CHECK(info.upper.value == 127);
        ASN1_TEST_CHECK(asn1_test_schema_type_constraint(loaded, 2, 0,
                                                         &info) == 1);
        ASN1_TEST_CHECK(info.kind == ASN1_CONSTRAINT_SIZE);
        ASN1_TEST_CHECK(info.lower.value == 0);
        ASN1_TEST_CHECK(info.upper.value == 64);
        ASN1_TEST_CHECK(asn1_test_schema_field_constraint(loaded, 4, 0, 0,
                                                         &info) == 1);
        ASN1_TEST_CHECK(info.kind == ASN1_CONSTRAINT_ENUM);
        ASN1_TEST_CHECK(info.enum_count == 3);
        ASN1_TEST_CHECK(info.enum_values[0] == 1);
        ASN1_TEST_CHECK(info.enum_values[1] == 2);
        ASN1_TEST_CHECK(info.enum_values[2] == 3);
        ASN1_TEST_CHECK(asn1_test_schema_field_constraint(loaded, 5, 0, 0,
                                                         &info) == 1);
        ASN1_TEST_CHECK(info.kind == ASN1_CONSTRAINT_MAX);
        ASN1_TEST_CHECK(info.upper_unbounded == 1);
    }

    /* 同一描述走运行时注册，逐字段比较两棵类型树。 */
    ASN1_TEST_CHECK(build_runtime_schema(ctx, &runtime) == 1);
    ASN1_TEST_CHECK(asn1_test_compare_schemas(loaded, runtime) == 0);
    ASN1_TEST_CHECK(asn1_test_compare_schemas(runtime, runtime) == 0);
    asn1_schema_destroy(runtime);
    asn1_schema_destroy(loaded);

    /* ===== 错误夹具：每次复制基线并重算校验和 ===== */

    /* 表描述符结构。 */
    {
        asn1_schema_table_t bad = make_table(base, TABLE_SIZE);
        asn1_schema_t *schema = NULL;
        bad.struct_size = sizeof(bad) - 1;
        ASN1_TEST_CHECK(asn1_schema_load(ctx, &bad, &schema) ==
                        ASN1_E_INVALID_CONFIG);
        ASN1_TEST_CHECK(schema == NULL);
        bad = make_table(base, TABLE_SIZE);
        bad.reserved = 1;
        ASN1_TEST_CHECK(asn1_schema_load(ctx, &bad, &schema) ==
                        ASN1_E_INVALID_CONFIG);
        ASN1_TEST_CHECK(schema == NULL);
    }
    ASN1_TEST_CHECK(expect_load_error(ctx, NULL, TABLE_SIZE,
                                      ASN1_E_INVALID_ARG));
    ASN1_TEST_CHECK(expect_load_error(ctx, base, 0, ASN1_E_INVALID_ARG));
    ASN1_TEST_CHECK(expect_load_error(ctx, base, 95, ASN1_E_SCHEMA_FORMAT));

    /* 头部字段。 */
    memcpy(work, base, TABLE_SIZE);
    work[0] = 0;
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 8, 0x00020000u);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));

    /* format_version 矩阵：major 0/2、minor 1、描述符与头部不一致均拒绝。 */
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 8, 0x00000000u);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 8, 0x00010001u);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));
    {
        asn1_schema_table_t bad = make_table(base, TABLE_SIZE);
        asn1_schema_t *schema = NULL;
        bad.format_version = 0;
        ASN1_TEST_CHECK(asn1_schema_load(ctx, &bad, &schema) ==
                        ASN1_E_SCHEMA_FORMAT);
        ASN1_TEST_CHECK(schema == NULL);
        bad = make_table(base, TABLE_SIZE);
        bad.format_version = 0x00010001u;
        ASN1_TEST_CHECK(asn1_schema_load(ctx, &bad, &schema) ==
                        ASN1_E_SCHEMA_FORMAT);
        ASN1_TEST_CHECK(schema == NULL);
    }

    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 12, 95);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));

    /* header_size 扩展：96/100/104 均可加载；108 基线见 test_schema_names。 */
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 12, 104);
    refresh_checksum(work);
    {
        asn1_schema_table_t ok = make_table(work, TABLE_SIZE);
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_load(ctx, &ok, &schema) == ASN1_OK);
        ASN1_TEST_CHECK(schema != NULL);
        ASN1_TEST_CHECK(asn1_test_schema_root_type_id(schema) == 4);
        asn1_schema_destroy(schema);
    }

    /* header_size == 96：root_type_id 位于未知尾部，视作 0 且正常加载。 */
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 12, 96);
    refresh_checksum(work);
    {
        asn1_schema_table_t ok = make_table(work, TABLE_SIZE);
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_load(ctx, &ok, &schema) == ASN1_OK);
        ASN1_TEST_CHECK(schema != NULL);
        ASN1_TEST_CHECK(asn1_test_schema_root_type_id(schema) == 0);
        asn1_schema_destroy(schema);
    }

    /* root_type_id：0 合法、越界拒绝。 */
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 96, 0);
    refresh_checksum(work);
    {
        asn1_schema_table_t ok = make_table(work, TABLE_SIZE);
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_load(ctx, &ok, &schema) == ASN1_OK);
        ASN1_TEST_CHECK(schema != NULL);
        ASN1_TEST_CHECK(asn1_test_schema_root_type_id(schema) == 0);
        asn1_schema_destroy(schema);
    }
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 96, 8);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));

    /* module_tag_mode 映射：0=AUTOMATIC→IMPLICIT、3=未声明→DEFAULT。 */
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 20, 0);
    refresh_checksum(work);
    {
        asn1_schema_table_t ok = make_table(work, TABLE_SIZE);
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_load(ctx, &ok, &schema) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_test_schema_module_tag_mode(schema) ==
                        ASN1_TAG_MODE_IMPLICIT);
        asn1_schema_destroy(schema);
    }
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 20, 3);
    refresh_checksum(work);
    {
        asn1_schema_table_t ok = make_table(work, TABLE_SIZE);
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_load(ctx, &ok, &schema) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_test_schema_module_tag_mode(schema) ==
                        ASN1_TAG_MODE_DEFAULT);
        asn1_schema_destroy(schema);
    }

    /* SIZE 单位：同一区间用于字符串（字节）与 SEQUENCE OF（元素数）。 */
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_TYPE_TABLE + 1u * 48u + 32u, 0);
    put_u32(work, OFF_TYPE_TABLE + 5u * 48u + 28u, 1);
    put_u32(work, OFF_TYPE_TABLE + 5u * 48u + 32u, 1);
    refresh_checksum(work);
    {
        asn1_schema_table_t ok = make_table(work, TABLE_SIZE);
        asn1_schema_t *schema = NULL;
        asn1_test_constraint_info info;
        ASN1_TEST_CHECK(asn1_schema_load(ctx, &ok, &schema) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_test_schema_type_constraint(schema, 6, 0,
                                                         &info) == 1);
        ASN1_TEST_CHECK(info.kind == ASN1_CONSTRAINT_SIZE);
        ASN1_TEST_CHECK(info.lower.value == 0);
        ASN1_TEST_CHECK(info.upper.value == 64);
        asn1_schema_destroy(schema);
    }
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 16, 0x04030201u);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 20, 4);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 24, 3);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 28, 2);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));
    memcpy(work, base, TABLE_SIZE);
    put_u64(work, 32, TABLE_SIZE + 1);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 84, 1);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));

    /* CRC 错误：直接翻转已写入的校验和。 */
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 80, crc32c_zeroed(work, TABLE_SIZE, 80, 4) ^ 1u);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));

    /* checksum 字段置 0：该字段按 0 参与计算，0 != 正确校验和故失败。 */
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 80, 0);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));

    /* 表偏移越界与区间重叠。 */
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 48, 0xFFFFu);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 56, 0xFFFFu);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 48, OFF_STRING_POOL);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 64, 0xFFFFu);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 72, 0xFFFFu);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));

    /* 字符串池非法。 */
    memcpy(work, base, TABLE_SIZE);
    work[OFF_STRING_POOL] = 'X';
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 44, 0);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_TYPE_TABLE, 0);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, 44, 1);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));

    /* 类型记录。 */
    memcpy(work, base, TABLE_SIZE);
    work[OFF_TYPE_TABLE + 7] = 0x02;
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));
    memcpy(work, base, TABLE_SIZE);
    put_u16(work, OFF_TYPE_TABLE + 4, 6);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_TYPE));
    memcpy(work, base, TABLE_SIZE);
    work[OFF_TYPE_TABLE + 6] = 3;
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_TYPE));
    memcpy(work, base, TABLE_SIZE);
    work[OFF_TYPE_TABLE + 8] = 4;
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_TYPE));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_TYPE_TABLE + 36, 1);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_TYPE_TABLE + 20, 100);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FIELD));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_TYPE_TABLE + 28, 100);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_CONSTRAINT));

    /* OF 元素引用：0、越界与非 OF 非零。 */
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_TYPE_TABLE + 5u * 48u + 16u, 0);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_TYPE));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_TYPE_TABLE + 5u * 48u + 16u, 99);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_TYPE));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_TYPE_TABLE + 16u, 1);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_TYPE));

    /* 类型组合：CHOICE + IMPLICIT。 */
    memcpy(work, base, TABLE_SIZE);
    work[OFF_TYPE_TABLE + 6u * 48u + 6u] = 2;
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_TYPE));

    /* 字段记录。 */
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_FIELD_TABLE + 4, 0);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_TYPE));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_FIELD_TABLE + 4, 99);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_TYPE));
    memcpy(work, base, TABLE_SIZE);
    put_u16(work, OFF_FIELD_TABLE + 8, 0x0004u);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_FIELD_TABLE + 12, 2);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_DEFAULT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_FIELD_TABLE + 16, 100);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_CONSTRAINT));
    /* SEQUENCE 中 OPTIONAL 字段与后继字段标签冲突。 */
    memcpy(work, base, TABLE_SIZE);
    put_u16(work, OFF_FIELD_TABLE + 8, ASN1_FIELD_OPTIONAL);
    put_u32(work, OFF_FIELD_TABLE + 32u + 4u, 1);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_TYPE));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_FIELD_TABLE + 2u * 32u + 4u, 1);
    put_u32(work, OFF_FIELD_TABLE + 3u * 32u + 4u, 1);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_TYPE));

    /* 约束记录。 */
    memcpy(work, base, TABLE_SIZE);
    put_u16(work, OFF_CONSTRAINT_TABLE, 5);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));
    memcpy(work, base, TABLE_SIZE);
    put_u16(work, OFF_CONSTRAINT_TABLE + 2, 0x0004u);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_CONSTRAINT_TABLE + 44, 1);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_CONSTRAINT_TABLE + 2u * 48u + 8u, 0); /* ENUM 空集 */
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));
    memcpy(work, base, TABLE_SIZE);
    put_i64(work, OFF_ENUM_ARRAY + 16u, 1); /* ENUM 重复取值 */
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_CONSTRAINT_TABLE + 2u * 48u + 4u, OFF_ENUM_ARRAY + 1);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_CONSTRAINT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_CONSTRAINT_TABLE + 2u * 48u + 4u, 0xFFFFu);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_CONSTRAINT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_CONSTRAINT_TABLE + 4, 1); /* 非 ENUM 携带枚举 */
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_CONSTRAINT_TABLE + 12, STR_FIELD_VALUE);
    put_u32(work, OFF_CONSTRAINT_TABLE + 16, 5);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));

    /* MAX 带下界：下界固定为 0，不得给出非零 lower_value。 */
    memcpy(work, base, TABLE_SIZE);
    put_i64(work, OFF_CONSTRAINT_TABLE + 3u * 48u + 28u, 5);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));

    /* BIGINT 十进制：前导零非法。 */
    memcpy(work, base, TABLE_SIZE);
    put_u16(work, OFF_CONSTRAINT_TABLE, 4);
    put_u32(work, OFF_CONSTRAINT_TABLE + 12, STR_DEC_LEADING_ZERO);
    put_u32(work, OFF_CONSTRAINT_TABLE + 16, 2);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_FORMAT));

    /* 默认值记录。 */
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_DEFAULT_TABLE + 4, 0);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_DEFAULT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_DEFAULT_TABLE, 0xFFFFu);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_DEFAULT));
    memcpy(work, base, TABLE_SIZE);
    put_u32(work, OFF_DEFAULT_TABLE, 16);
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_DEFAULT));
    memcpy(work, base, TABLE_SIZE);
    work[OFF_DEFAULT_BYTES + 1] = 0x05; /* 长度超出可用内容 */
    refresh_checksum(work);
    ASN1_TEST_CHECK(expect_load_error(ctx, work, TABLE_SIZE,
                                      ASN1_E_SCHEMA_DEFAULT));

    asn1_ctx_destroy(ctx);
    return 0;
}
