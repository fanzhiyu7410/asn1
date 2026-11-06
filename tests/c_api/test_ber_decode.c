/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * BER 解码最小闭环：合法 TLV、嵌套、截断、长度越界、深度超限、尾随拒绝、
 * COPY_INPUT 生命周期与错误详情。
 */
#include <asn1/asn1.h>

#include <stddef.h>
#include <string.h>

#include "check.h"

int main(void)
{
    asn1_ctx_config_t config;
    asn1_ctx_config_init(&config);
    asn1_ctx_t *ctx = NULL;
    ASN1_TEST_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_OK);

    /* 单层 SEQUENCE + INTEGER。 */
    static const uint8_t basic[] = {0x30, 0x03, 0x02, 0x01, 0x05};
    asn1_doc_t *doc = NULL;
    size_t consumed = 0;
    ASN1_TEST_CHECK(asn1_decode_buffer(ctx, basic, sizeof(basic), NULL, &doc,
                                       &consumed) == ASN1_OK);
    ASN1_TEST_CHECK(doc != NULL);
    ASN1_TEST_CHECK(consumed == sizeof(basic));
    const asn1_node_t *root = asn1_doc_root(doc);
    ASN1_TEST_CHECK(root != NULL);
    ASN1_TEST_CHECK(asn1_node_tag_number(root) == 16);
    ASN1_TEST_CHECK(asn1_node_child_count(root) == 1);
    const asn1_node_t *child = asn1_node_child_at(root, 0);
    ASN1_TEST_CHECK(child != NULL);
    ASN1_TEST_CHECK(asn1_node_tag_number(child) == 2);
    ASN1_TEST_CHECK(asn1_node_parent(child) == root);
    ASN1_TEST_CHECK(asn1_node_offset(child) == 2);
    size_t tlv_size = 0;
    const uint8_t *tlv = asn1_node_tlv(child, &tlv_size);
    ASN1_TEST_CHECK(tlv == basic + 2);
    ASN1_TEST_CHECK(tlv_size == 3);
    const uint8_t *content = NULL;
    size_t content_size = 0;
    ASN1_TEST_CHECK(asn1_node_content(child, &content, &content_size) ==
                    ASN1_OK);
    ASN1_TEST_CHECK(content_size == 1);
    ASN1_TEST_CHECK(content == basic + 4);
    int64_t int_value = 0;
    ASN1_TEST_CHECK(asn1_node_get_int64(child, &int_value) == ASN1_OK);
    ASN1_TEST_CHECK(int_value == 5);
    asn1_doc_destroy(doc);

    /* 嵌套两层。 */
    static const uint8_t nested[] = {0x30, 0x05, 0x30, 0x03,
                                     0x02, 0x01, 0x05};
    ASN1_TEST_CHECK(asn1_decode_buffer(ctx, nested, sizeof(nested), NULL, &doc,
                                       &consumed) == ASN1_OK);
    ASN1_TEST_CHECK(consumed == sizeof(nested));
    root = asn1_doc_root(doc);
    child = asn1_node_child_at(root, 0);
    ASN1_TEST_CHECK(child != NULL);
    const asn1_node_t *grandchild = asn1_node_child_at(child, 0);
    ASN1_TEST_CHECK(grandchild != NULL);
    ASN1_TEST_CHECK(asn1_node_tag_number(grandchild) == 2);
    asn1_doc_destroy(doc);

    /* 截断：内容长度越过输入末尾。 */
    static const uint8_t truncated[] = {0x30, 0x05, 0x02, 0x01};
    consumed = 1234;
    doc = NULL;
    ASN1_TEST_CHECK(asn1_decode_buffer(ctx, truncated, sizeof(truncated), NULL,
                                       &doc, &consumed) == ASN1_E_TRUNCATED);
    ASN1_TEST_CHECK(doc == NULL);
    ASN1_TEST_CHECK(consumed == 1234);

    asn1_error_info_t info;
    info.struct_size = sizeof(info);
    ASN1_TEST_CHECK(asn1_ctx_get_error(ctx, &info) == ASN1_OK);
    ASN1_TEST_CHECK(info.code == ASN1_E_TRUNCATED);
    ASN1_TEST_CHECK(info.message != NULL);
    ASN1_TEST_CHECK(info.callback_code == 0);
    ASN1_TEST_CHECK(info.offset == 4);
    ASN1_TEST_CHECK(info.depth == 0);
    ASN1_TEST_CHECK(info.path == NULL);
    asn1_ctx_clear_error(ctx);
    info.struct_size = sizeof(info);
    ASN1_TEST_CHECK(asn1_ctx_get_error(ctx, &info) == ASN1_OK);
    ASN1_TEST_CHECK(info.code == ASN1_OK);
    ASN1_TEST_CHECK(info.offset == SIZE_MAX);

    /* 长度八位组过多。 */
    static const uint8_t bad_length[] = {0x30, 0x89};
    ASN1_TEST_CHECK(asn1_decode_buffer(ctx, bad_length, sizeof(bad_length),
                                       NULL, &doc, &consumed) ==
                    ASN1_E_MALFORMED_LENGTH);

    /* 声明长度越界但八位组合法。 */
    static const uint8_t huge_length[] = {0x30, 0x82, 0xFF, 0xFF};
    ASN1_TEST_CHECK(asn1_decode_buffer(ctx, huge_length, sizeof(huge_length),
                                       NULL, &doc, &consumed) ==
                    ASN1_E_TRUNCATED);

    /* 多字节 tag number 已支持。 */
    static const uint8_t high_tag[] = {0x9F, 0x28, 0x00};
    ASN1_TEST_CHECK(asn1_decode_buffer(ctx, high_tag, sizeof(high_tag), NULL,
                                       &doc, &consumed) == ASN1_OK);
    ASN1_TEST_CHECK(doc != NULL);
    ASN1_TEST_CHECK(asn1_node_tag_class(asn1_doc_root(doc)) ==
                    ASN1_TAG_CONTEXT);
    ASN1_TEST_CHECK(asn1_node_tag_number(asn1_doc_root(doc)) == 40);
    asn1_doc_destroy(doc);

    /* BER 不定长：单层、嵌套、TLV 含 EOC。 */
    static const uint8_t indefinite[] = {0x30, 0x80, 0x02, 0x01,
                                         0x05, 0x00, 0x00};
    ASN1_TEST_CHECK(asn1_decode_buffer(ctx, indefinite, sizeof(indefinite),
                                       NULL, &doc, &consumed) == ASN1_OK);
    ASN1_TEST_CHECK(doc != NULL);
    ASN1_TEST_CHECK(asn1_node_is_indefinite(asn1_doc_root(doc)) == 1);
    ASN1_TEST_CHECK(asn1_node_child_count(asn1_doc_root(doc)) == 1);
    ASN1_TEST_CHECK(asn1_node_tag_number(asn1_node_child_at(
                        asn1_doc_root(doc), 0)) == 2);
    {
        size_t tlv_size = 0;
        ASN1_TEST_CHECK(asn1_node_tlv(asn1_doc_root(doc), &tlv_size) != NULL);
        ASN1_TEST_CHECK(tlv_size == sizeof(indefinite));
    }
    asn1_doc_destroy(doc);

    static const uint8_t nested_indefinite[] = {
        0x30, 0x80, 0x02, 0x01, 0x05, 0x30, 0x80,
        0x02, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00};
    ASN1_TEST_CHECK(asn1_decode_buffer(ctx, nested_indefinite,
                                       sizeof(nested_indefinite), NULL, &doc,
                                       &consumed) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_node_child_count(asn1_doc_root(doc)) == 2);
    const asn1_node_t *nested_child = asn1_node_child_at(asn1_doc_root(doc), 1);
    ASN1_TEST_CHECK(nested_child != NULL);
    ASN1_TEST_CHECK(asn1_node_is_indefinite(nested_child) == 1);
    ASN1_TEST_CHECK(asn1_node_tag_number(nested_child) == 16);
    asn1_doc_destroy(doc);

    /* 缺少 EOC 的不定长按截断处理。 */
    static const uint8_t missing_eoc[] = {0x30, 0x80, 0x02, 0x01, 0x05};
    ASN1_TEST_CHECK(asn1_decode_buffer(ctx, missing_eoc, sizeof(missing_eoc),
                                       NULL, &doc, &consumed) ==
                    ASN1_E_TRUNCATED);
    ASN1_TEST_CHECK(doc == NULL);

    /* 单层不定长 OCTET STRING 分段合并。 */
    static const uint8_t indefinite_octets[] = {
        0x24, 0x80, 0x04, 0x01, 0x41, 0x04, 0x01, 0x42, 0x00, 0x00};
    ASN1_TEST_CHECK(asn1_decode_buffer(ctx, indefinite_octets,
                                       sizeof(indefinite_octets), NULL, &doc,
                                       &consumed) == ASN1_OK);
    {
        const uint8_t *data = NULL;
        size_t size = 0;
        ASN1_TEST_CHECK(asn1_node_get_octets(asn1_doc_root(doc), &data,
                                             &size) == ASN1_OK);
        ASN1_TEST_CHECK(size == 2);
        ASN1_TEST_CHECK(data[0] == 0x41 && data[1] == 0x42);
    }
    asn1_doc_destroy(doc);

    /* 不定长构造字符串（UTF8String）分段合并。 */
    static const uint8_t indefinite_utf8[] = {
        0x2C, 0x80, 0x0C, 0x02, 0x41, 0x42, 0x0C, 0x02,
        0x43, 0x44, 0x00, 0x00};
    ASN1_TEST_CHECK(asn1_decode_buffer(ctx, indefinite_utf8,
                                       sizeof(indefinite_utf8), NULL, &doc,
                                       &consumed) == ASN1_OK);
    {
        const uint8_t *text = NULL;
        size_t size = 0;
        ASN1_TEST_CHECK(asn1_node_get_raw_string(asn1_doc_root(doc), &text,
                                                 &size) == ASN1_OK);
        ASN1_TEST_CHECK(size == 4);
        ASN1_TEST_CHECK(memcmp(text, "ABCD", 4) == 0);
    }
    asn1_doc_destroy(doc);

    /* 不定长 BIT STRING 分段按位累加（第二段带 4 个 unused bits）。 */
    static const uint8_t indefinite_bits[] = {
        0x23, 0x80, 0x03, 0x02, 0x00, 0xAA, 0x03,
        0x02, 0x04, 0xF0, 0x00, 0x00};
    ASN1_TEST_CHECK(asn1_decode_buffer(ctx, indefinite_bits,
                                       sizeof(indefinite_bits), NULL, &doc,
                                       &consumed) == ASN1_OK);
    {
        const uint8_t *data = NULL;
        size_t size = 0;
        size_t bit_length = 0;
        uint8_t unused = 9;
        ASN1_TEST_CHECK(asn1_node_get_bits(asn1_doc_root(doc), &data, &size,
                                           &bit_length, &unused) == ASN1_OK);
        ASN1_TEST_CHECK(size == 2);
        ASN1_TEST_CHECK(bit_length == 12);
        ASN1_TEST_CHECK(unused == 4);
        ASN1_TEST_CHECK(data[0] == 0xAA && data[1] == 0xF0);
    }
    asn1_doc_destroy(doc);

    /* 顶层裸 EOC 始终拒绝。 */
    static const uint8_t eoc[] = {0x00};
    ASN1_TEST_CHECK(asn1_decode_buffer(ctx, eoc, sizeof(eoc), NULL, &doc,
                                       &consumed) == ASN1_E_MALFORMED_TAG);

    /* 尾随数据默认拒绝，可显式允许。 */
    static const uint8_t trailing[] = {0x02, 0x01, 0x00, 0x05};
    consumed = 999;
    ASN1_TEST_CHECK(asn1_decode_buffer(ctx, trailing, sizeof(trailing), NULL,
                                       &doc, &consumed) ==
                    ASN1_E_TRAILING_DATA);
    ASN1_TEST_CHECK(doc == NULL);
    ASN1_TEST_CHECK(consumed == 999);

    asn1_decode_options_t options;
    asn1_decode_options_init(&options);
    options.flags = ASN1_DECODE_ALLOW_TRAILING;
    consumed = 0;
    ASN1_TEST_CHECK(asn1_decode_buffer(ctx, trailing, sizeof(trailing),
                                       &options, &doc, &consumed) == ASN1_OK);
    ASN1_TEST_CHECK(consumed == 3);
    asn1_doc_destroy(doc);

    /* COPY_INPUT：复制后调用方缓冲可被改写。 */
    uint8_t borrowed[] = {0x02, 0x01, 0x05};
    ASN1_TEST_CHECK(asn1_decode_buffer(ctx, borrowed, sizeof(borrowed), NULL,
                                       &doc, &consumed) == ASN1_OK);
    const asn1_node_t *borrowed_node = asn1_doc_root(doc);
    borrowed[2] = 0xFF;
    ASN1_TEST_CHECK(asn1_node_get_int64(borrowed_node, &int_value) == ASN1_OK);
    ASN1_TEST_CHECK(int_value == -1);
    asn1_doc_destroy(doc);

    uint8_t copied[] = {0x02, 0x01, 0x05};
    asn1_decode_options_init(&options);
    options.flags = ASN1_DECODE_COPY_INPUT;
    ASN1_TEST_CHECK(asn1_decode_buffer(ctx, copied, sizeof(copied), &options,
                                       &doc, &consumed) == ASN1_OK);
    copied[2] = 0xFF;
    const asn1_node_t *copied_node = asn1_doc_root(doc);
    ASN1_TEST_CHECK(asn1_node_get_int64(copied_node, &int_value) == ASN1_OK);
    ASN1_TEST_CHECK(int_value == 5);
    asn1_doc_destroy(doc);

    /* 选项校验。 */
    asn1_decode_options_init(&options);
    options.struct_size = 0;
    ASN1_TEST_CHECK(asn1_decode_buffer(ctx, basic, sizeof(basic), &options,
                                       &doc, &consumed) ==
                    ASN1_E_INVALID_CONFIG);
    asn1_decode_options_init(&options);
    options.encoding = ASN1_ENCODING_NONE;
    ASN1_TEST_CHECK(asn1_decode_buffer(ctx, basic, sizeof(basic), &options,
                                       &doc, &consumed) ==
                    ASN1_E_UNSUPPORTED_ENCODING);
    asn1_decode_options_init(&options);
    options.flags = ASN1_DECODE_STRICT_SCHEMA;
    ASN1_TEST_CHECK(asn1_decode_buffer(ctx, basic, sizeof(basic), &options,
                                       &doc, &consumed) ==
                    ASN1_E_INVALID_ARG);
    asn1_decode_options_init(&options);
    options.max_depth = 128; /* 大于上下文默认 64 */
    ASN1_TEST_CHECK(asn1_decode_buffer(ctx, basic, sizeof(basic), &options,
                                       &doc, &consumed) ==
                    ASN1_E_INVALID_CONFIG);

    asn1_ctx_destroy(ctx);

    /* 深度上限：上下文 max_depth = 1。 */
    asn1_ctx_config_init(&config);
    config.max_depth = 1;
    ASN1_TEST_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_decode_buffer(ctx, nested, sizeof(nested), NULL, &doc,
                                       &consumed) == ASN1_E_DEPTH_LIMIT);
    ASN1_TEST_CHECK(doc == NULL);

    /* decode_reader：非法 reader 配置。 */
    asn1_reader_t reader;
    reader.struct_size = sizeof(reader);
    reader.user = NULL;
    reader.read = NULL;
    ASN1_TEST_CHECK(asn1_decode_reader(ctx, &reader, NULL, &doc, &consumed) ==
                    ASN1_E_INVALID_CONFIG);
    ASN1_TEST_CHECK(doc == NULL);
    asn1_ctx_destroy(ctx);

    return 0;
}
