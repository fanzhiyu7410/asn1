/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * 语义读取：BOOLEAN、INTEGER、OCTET/BIT STRING、OID、字符串、大整数与时间。
 */
#include <asn1/asn1.h>

#include <stddef.h>
#include <string.h>

#include "check.h"

static asn1_doc_t *decode_one(asn1_ctx_t *ctx, const uint8_t *data,
                              size_t size)
{
    asn1_doc_t *doc = NULL;
    size_t consumed = 0;
    if (asn1_decode_buffer(ctx, data, size, NULL, &doc, &consumed) != ASN1_OK) {
        return NULL;
    }
    return doc;
}

int main(void)
{
    asn1_ctx_config_t config;
    asn1_ctx_config_init(&config);
    asn1_ctx_t *ctx = NULL;
    ASN1_TEST_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_OK);

    /* BOOLEAN。 */
    static const uint8_t bool_false[] = {0x01, 0x01, 0x00};
    asn1_doc_t *doc = decode_one(ctx, bool_false, sizeof(bool_false));
    ASN1_TEST_CHECK(doc != NULL);
    int bool_value = -1;
    ASN1_TEST_CHECK(asn1_node_get_bool(asn1_doc_root(doc), &bool_value) ==
                    ASN1_OK);
    ASN1_TEST_CHECK(bool_value == 0);
    asn1_doc_destroy(doc);

    static const uint8_t bool_true[] = {0x01, 0x01, 0xFF};
    doc = decode_one(ctx, bool_true, sizeof(bool_true));
    ASN1_TEST_CHECK(doc != NULL);
    ASN1_TEST_CHECK(asn1_node_get_bool(asn1_doc_root(doc), &bool_value) ==
                    ASN1_OK);
    ASN1_TEST_CHECK(bool_value == 1);
    asn1_doc_destroy(doc);

    /* DER 下 BOOLEAN 非 0xFF/0x00 在解码阶段即被拒。 */
    static const uint8_t bool_der_bad[] = {0x01, 0x01, 0x01};
    asn1_decode_options_t options;
    asn1_decode_options_init(&options);
    options.encoding = ASN1_ENCODING_DER;
    size_t consumed = 0;
    doc = NULL;
    ASN1_TEST_CHECK(asn1_decode_buffer(ctx, bool_der_bad, sizeof(bool_der_bad),
                                       &options, &doc, &consumed) ==
                    ASN1_E_NON_CANONICAL);
    ASN1_TEST_CHECK(doc == NULL);

    /* INTEGER：负数、正数、越界。 */
    static const uint8_t integer_neg[] = {0x02, 0x01, 0xFF};
    doc = decode_one(ctx, integer_neg, sizeof(integer_neg));
    ASN1_TEST_CHECK(doc != NULL);
    int64_t int_value = 0;
    ASN1_TEST_CHECK(asn1_node_get_int64(asn1_doc_root(doc), &int_value) ==
                    ASN1_OK);
    ASN1_TEST_CHECK(int_value == -1);
    asn1_doc_destroy(doc);

    static const uint8_t integer_255[] = {0x02, 0x02, 0x00, 0xFF};
    doc = decode_one(ctx, integer_255, sizeof(integer_255));
    ASN1_TEST_CHECK(doc != NULL);
    ASN1_TEST_CHECK(asn1_node_get_int64(asn1_doc_root(doc), &int_value) ==
                    ASN1_OK);
    ASN1_TEST_CHECK(int_value == 255);
    asn1_doc_destroy(doc);

    static const uint8_t integer_range[] = {
        0x02, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    doc = decode_one(ctx, integer_range, sizeof(integer_range));
    ASN1_TEST_CHECK(doc != NULL);
    ASN1_TEST_CHECK(asn1_node_get_int64(asn1_doc_root(doc), &int_value) ==
                    ASN1_E_RANGE);
    asn1_doc_destroy(doc);

    /* 构造 OCTET STRING 合并。 */
    static const uint8_t octets_constructed[] = {
        0x24, 0x09, 0x04, 0x03, 0x01, 0x02, 0x03, 0x04, 0x02, 0x04, 0x05};
    doc = decode_one(ctx, octets_constructed, sizeof(octets_constructed));
    ASN1_TEST_CHECK(doc != NULL);
    const uint8_t *data = NULL;
    size_t size = 0;
    ASN1_TEST_CHECK(asn1_node_get_octets(asn1_doc_root(doc), &data, &size) ==
                    ASN1_OK);
    ASN1_TEST_CHECK(size == 5);
    ASN1_TEST_CHECK(data != NULL);
    ASN1_TEST_CHECK(memcmp(data, "\x01\x02\x03\x04\x05", 5) == 0);
    ASN1_TEST_CHECK(asn1_node_content(asn1_doc_root(doc), &data, &size) ==
                    ASN1_E_INVALID_STATE);
    asn1_doc_destroy(doc);

    /* BIT STRING：非零与零值。 */
    static const uint8_t bits[] = {0x03, 0x02, 0x04, 0xA0};
    doc = decode_one(ctx, bits, sizeof(bits));
    ASN1_TEST_CHECK(doc != NULL);
    size_t bit_length = 0;
    uint8_t unused = 0;
    ASN1_TEST_CHECK(asn1_node_get_bits(asn1_doc_root(doc), &data, &size,
                                       &bit_length, &unused) == ASN1_OK);
    ASN1_TEST_CHECK(size == 1);
    ASN1_TEST_CHECK(bit_length == 4);
    ASN1_TEST_CHECK(unused == 4);
    ASN1_TEST_CHECK(data != NULL && data[0] == 0xA0);
    asn1_doc_destroy(doc);

    static const uint8_t bits_zero[] = {0x03, 0x01, 0x00};
    doc = decode_one(ctx, bits_zero, sizeof(bits_zero));
    ASN1_TEST_CHECK(doc != NULL);
    ASN1_TEST_CHECK(asn1_node_get_bits(asn1_doc_root(doc), &data, &size,
                                       &bit_length, &unused) == ASN1_OK);
    ASN1_TEST_CHECK(size == 0);
    ASN1_TEST_CHECK(bit_length == 0);
    ASN1_TEST_CHECK(unused == 0);
    asn1_doc_destroy(doc);

    /* OID。 */
    static const uint8_t oid[] = {0x06, 0x03, 0x55, 0x04, 0x03};
    doc = decode_one(ctx, oid, sizeof(oid));
    ASN1_TEST_CHECK(doc != NULL);
    const char *text = NULL;
    ASN1_TEST_CHECK(asn1_node_get_oid(asn1_doc_root(doc), &text, &size) ==
                    ASN1_OK);
    ASN1_TEST_CHECK(size == 7);
    ASN1_TEST_CHECK(strcmp(text, "2.5.4.3") == 0);
    asn1_doc_destroy(doc);

    /* 字符串：PrintableString、UTF8String、T61 拒绝。 */
    static const uint8_t printable[] = {0x13, 0x03, 0x61, 0x62, 0x63};
    doc = decode_one(ctx, printable, sizeof(printable));
    ASN1_TEST_CHECK(doc != NULL);
    ASN1_TEST_CHECK(asn1_node_get_utf8(asn1_doc_root(doc), &text, &size) ==
                    ASN1_OK);
    ASN1_TEST_CHECK(size == 3);
    ASN1_TEST_CHECK(strcmp(text, "abc") == 0);
    ASN1_TEST_CHECK(asn1_node_get_raw_string(asn1_doc_root(doc), &data,
                                             &size) == ASN1_OK);
    ASN1_TEST_CHECK(size == 3);
    asn1_doc_destroy(doc);

    static const uint8_t utf8_chinese[] = {0x0C, 0x03, 0xE4, 0xB8, 0xAD};
    doc = decode_one(ctx, utf8_chinese, sizeof(utf8_chinese));
    ASN1_TEST_CHECK(doc != NULL);
    ASN1_TEST_CHECK(asn1_node_get_utf8(asn1_doc_root(doc), &text, &size) ==
                    ASN1_OK);
    ASN1_TEST_CHECK(size == 3);
    asn1_doc_destroy(doc);

    static const uint8_t t61[] = {0x14, 0x01, 0x41};
    doc = decode_one(ctx, t61, sizeof(t61));
    ASN1_TEST_CHECK(doc != NULL);
    ASN1_TEST_CHECK(asn1_node_get_utf8(asn1_doc_root(doc), &text, &size) ==
                    ASN1_E_CONVERSION);
    ASN1_TEST_CHECK(asn1_node_get_raw_string(asn1_doc_root(doc), &data,
                                             &size) == ASN1_OK);
    ASN1_TEST_CHECK(size == 1);
    asn1_doc_destroy(doc);

    /* 大整数十进制。 */
    static const uint8_t bigint_neg[] = {0x02, 0x01, 0x80};
    doc = decode_one(ctx, bigint_neg, sizeof(bigint_neg));
    ASN1_TEST_CHECK(doc != NULL);
    ASN1_TEST_CHECK(asn1_node_get_bigint_decimal(asn1_doc_root(doc), &text,
                                                 &size) == ASN1_OK);
    ASN1_TEST_CHECK(strcmp(text, "-128") == 0);
    ASN1_TEST_CHECK(size == 4);
    asn1_doc_destroy(doc);

    static const uint8_t bigint_255[] = {0x02, 0x02, 0x00, 0xFF};
    doc = decode_one(ctx, bigint_255, sizeof(bigint_255));
    ASN1_TEST_CHECK(doc != NULL);
    ASN1_TEST_CHECK(asn1_node_get_bigint_decimal(asn1_doc_root(doc), &text,
                                                 &size) == ASN1_OK);
    ASN1_TEST_CHECK(strcmp(text, "255") == 0);
    asn1_doc_destroy(doc);

    /* 时间：UTCTime、GeneralizedTime 小数、DER 缺秒。 */
    static const uint8_t utc_time[] = {
        0x17, 0x0D, 0x39, 0x39, 0x30, 0x31, 0x30, 0x31,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A};
    doc = decode_one(ctx, utc_time, sizeof(utc_time));
    ASN1_TEST_CHECK(doc != NULL);
    asn1_time_t time;
    time.struct_size = sizeof(time);
    ASN1_TEST_CHECK(asn1_node_get_time(asn1_doc_root(doc), &time) == ASN1_OK);
    ASN1_TEST_CHECK(time.year == 1999);
    ASN1_TEST_CHECK(time.month == 1);
    ASN1_TEST_CHECK(time.day == 1);
    ASN1_TEST_CHECK(time.hour == 0);
    ASN1_TEST_CHECK((time.flags & ASN1_TIME_UTC) != 0);
    ASN1_TEST_CHECK((time.flags & ASN1_TIME_HAS_OFFSET) == 0);
    ASN1_TEST_CHECK((time.flags & ASN1_TIME_LOCAL) == 0);
    asn1_doc_destroy(doc);

    static const uint8_t generalized[] = {
        0x18, 0x11, 0x32, 0x30, 0x32, 0x34, 0x30, 0x31, 0x30,
        0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2E, 0x35, 0x5A};
    doc = decode_one(ctx, generalized, sizeof(generalized));
    ASN1_TEST_CHECK(doc != NULL);
    time.struct_size = sizeof(time);
    ASN1_TEST_CHECK(asn1_node_get_time(asn1_doc_root(doc), &time) == ASN1_OK);
    ASN1_TEST_CHECK(time.year == 2024);
    ASN1_TEST_CHECK(time.nanosecond == 500000000);
    ASN1_TEST_CHECK((time.flags & ASN1_TIME_GENERALIZED) != 0);
    ASN1_TEST_CHECK((time.flags & ASN1_TIME_FRACTIONAL) != 0);
    asn1_doc_destroy(doc);

    static const uint8_t utc_der_no_seconds[] = {
        0x17, 0x0B, 0x39, 0x39, 0x30, 0x31, 0x30, 0x31,
        0x30, 0x30, 0x30, 0x30, 0x5A};
    asn1_decode_options_init(&options);
    options.encoding = ASN1_ENCODING_DER;
    doc = NULL;
    ASN1_TEST_CHECK(asn1_decode_buffer(ctx, utc_der_no_seconds,
                                       sizeof(utc_der_no_seconds), &options,
                                       &doc, &consumed) ==
                    ASN1_E_NON_CANONICAL);
    ASN1_TEST_CHECK(doc == NULL);

    /* BER 本地时间：无偏移。 */
    static const uint8_t utc_local[] = {
        0x17, 0x0A, 0x39, 0x39, 0x30, 0x31,
        0x30, 0x31, 0x30, 0x30, 0x30, 0x30};
    doc = decode_one(ctx, utc_local, sizeof(utc_local));
    ASN1_TEST_CHECK(doc != NULL);
    time.struct_size = sizeof(time);
    ASN1_TEST_CHECK(asn1_node_get_time(asn1_doc_root(doc), &time) == ASN1_OK);
    ASN1_TEST_CHECK((time.flags & ASN1_TIME_LOCAL) != 0);
    ASN1_TEST_CHECK((time.flags & ASN1_TIME_HAS_OFFSET) == 0);
    ASN1_TEST_CHECK(time.utc_offset_minutes == 0);
    asn1_doc_destroy(doc);

    /* 类型不匹配。 */
    static const uint8_t integer_node[] = {0x02, 0x01, 0x05};
    doc = decode_one(ctx, integer_node, sizeof(integer_node));
    ASN1_TEST_CHECK(doc != NULL);
    ASN1_TEST_CHECK(asn1_node_get_octets(asn1_doc_root(doc), &data, &size) ==
                    ASN1_E_INVALID_VALUE);
    ASN1_TEST_CHECK(asn1_node_get_oid(asn1_doc_root(doc), &text, &size) ==
                    ASN1_E_INVALID_VALUE);
    asn1_doc_destroy(doc);

    asn1_ctx_destroy(ctx);
    return 0;
}
