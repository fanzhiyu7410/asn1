/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * 编码器 C API：缓冲与 writer 两种出口、通用 DER 规范化、输出预算、
 * writer 失败包装、输出缓冲所有权与 schema 拒绝路径。
 */
#include <asn1/asn1.h>

#include <stddef.h>
#include <string.h>

#include "check.h"

/* ---------- 辅助 ---------- */

typedef struct writer_state {
    uint8_t bytes[256];
    size_t size;
    size_t calls;
    asn1_err_t result;
} writer_state_t;

static asn1_err_t capture_write(void *user, const uint8_t *data, size_t size)
{
    writer_state_t *state = (writer_state_t *)user;
    state->calls += 1;
    if (size > sizeof(state->bytes) - state->size) {
        return (asn1_err_t)99;
    }
    memcpy(state->bytes + state->size, data, size);
    state->size += size;
    return state->result;
}

static int bytes_equal(const uint8_t *actual, size_t actual_size,
                       const uint8_t *expected, size_t expected_size)
{
    if (actual_size != expected_size) {
        return 0;
    }
    return memcmp(actual, expected, expected_size) == 0;
}

/* 创建文档并建立根节点。 */
static asn1_err_t open_doc(asn1_ctx_t *ctx, asn1_doc_t **out_doc,
                           asn1_node_t **out_root,
                           asn1_tag_class_t tag_class, uint32_t tag_number,
                           int constructed)
{
    asn1_doc_t *doc = NULL;
    asn1_err_t rc = asn1_doc_create(ctx, &doc);
    if (rc != ASN1_OK) {
        return rc;
    }
    asn1_node_t *root = NULL;
    rc = asn1_node_create(doc, NULL, tag_class, tag_number, constructed, &root);
    if (rc != ASN1_OK) {
        asn1_doc_destroy(doc);
        return rc;
    }
    *out_doc = doc;
    *out_root = root;
    return ASN1_OK;
}

static asn1_err_t add_child(asn1_doc_t *doc, asn1_node_t *parent,
                            asn1_tag_class_t tag_class, uint32_t tag_number,
                            int constructed, asn1_node_t **out_node)
{
    return asn1_node_create(doc, parent, tag_class, tag_number, constructed,
                            out_node);
}

int main(void)
{
    /* ---------- 选项初始化 ---------- */
    asn1_encode_options_t options;
    asn1_encode_options_init(&options);
    ASN1_TEST_CHECK(options.struct_size == sizeof(asn1_encode_options_t));
    ASN1_TEST_CHECK(options.encoding == ASN1_ENCODING_DER);
    ASN1_TEST_CHECK(options.schema == NULL);
    ASN1_TEST_CHECK(options.flags == 0);
    ASN1_TEST_CHECK(options.reserved[0] == 0 && options.reserved[1] == 0 &&
                    options.reserved[2] == 0 && options.reserved[3] == 0);

    asn1_ctx_config_t config;
    asn1_ctx_config_init(&config);
    asn1_ctx_t *ctx = NULL;
    ASN1_TEST_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_OK);

    asn1_buf_t buf;
    buf.data = NULL;
    buf.size = 0;
    buf.capacity = 0;

    /* ---------- 空文档 / 未封存 ---------- */
    asn1_doc_t *doc = NULL;
    ASN1_TEST_CHECK(asn1_doc_create(ctx, &doc) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, &buf) ==
                    ASN1_E_INVALID_STATE);
    ASN1_TEST_CHECK(buf.data == NULL && buf.size == 0 && buf.capacity == 0);
    ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_E_INVALID_STATE);
    asn1_doc_destroy(doc);

    /* ---------- 单节点各类型 ---------- */
    {
        static const uint8_t expected[] = {0x02, 0x01, 0x05};
        asn1_node_t *root = NULL;
        ASN1_TEST_CHECK(open_doc(ctx, &doc, &root, ASN1_TAG_UNIVERSAL, 2, 0) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_int64(root, 5) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, expected,
                                    sizeof(expected)));
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(buf.data == NULL && buf.size == 0 && buf.capacity == 0);
        asn1_doc_destroy(doc);
    }

    {
        /* INTEGER -1：负值最短补码。 */
        static const uint8_t expected[] = {0x02, 0x01, 0xFF};
        asn1_node_t *root = NULL;
        ASN1_TEST_CHECK(open_doc(ctx, &doc, &root, ASN1_TAG_UNIVERSAL, 2, 0) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_int64(root, -1) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, expected,
                                    sizeof(expected)));
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        asn1_doc_destroy(doc);
    }

    {
        /* BOOLEAN FALSE / TRUE：set_bool 写出 0x00 / 0xFF。 */
        static const uint8_t false_bytes[] = {0x01, 0x01, 0x00};
        static const uint8_t true_bytes[] = {0x01, 0x01, 0xFF};
        asn1_node_t *root = NULL;
        ASN1_TEST_CHECK(open_doc(ctx, &doc, &root, ASN1_TAG_UNIVERSAL, 1, 0) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_bool(root, 0) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, false_bytes,
                                    sizeof(false_bytes)));
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        asn1_doc_destroy(doc);

        ASN1_TEST_CHECK(open_doc(ctx, &doc, &root, ASN1_TAG_UNIVERSAL, 1, 0) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_bool(root, 1) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, true_bytes,
                                    sizeof(true_bytes)));
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        asn1_doc_destroy(doc);
    }

    {
        /* 空 OCTET STRING 与两字节 OCTET STRING。 */
        static const uint8_t empty_bytes[] = {0x04, 0x00};
        static const uint8_t two_bytes[] = {0x04, 0x02, 0xAB, 0xCD};
        static const uint8_t payload[] = {0xAB, 0xCD};
        asn1_node_t *root = NULL;
        ASN1_TEST_CHECK(open_doc(ctx, &doc, &root, ASN1_TAG_UNIVERSAL, 4, 0) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_content(root, NULL, 0) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, empty_bytes,
                                    sizeof(empty_bytes)));
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        asn1_doc_destroy(doc);

        ASN1_TEST_CHECK(open_doc(ctx, &doc, &root, ASN1_TAG_UNIVERSAL, 4, 0) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_content(root, payload,
                                              sizeof(payload)) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, two_bytes,
                                    sizeof(two_bytes)));
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        asn1_doc_destroy(doc);
    }

    {
        /* BIT STRING：内容首字节为 unused-bits 计数。 */
        static const uint8_t content[] = {0x04, 0xA0};
        static const uint8_t expected[] = {0x03, 0x02, 0x04, 0xA0};
        asn1_node_t *root = NULL;
        ASN1_TEST_CHECK(open_doc(ctx, &doc, &root, ASN1_TAG_UNIVERSAL, 3, 0) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_content(root, content,
                                              sizeof(content)) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, expected,
                                    sizeof(expected)));
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        asn1_doc_destroy(doc);
    }

    {
        /* OID 2.5.4.3 与 UTF8String。 */
        static const uint8_t oid_bytes[] = {0x06, 0x03, 0x55, 0x04, 0x03};
        static const uint8_t utf8_bytes[] = {0x0C, 0x03, 0xE4, 0xB8, 0xAD};
        asn1_node_t *root = NULL;
        ASN1_TEST_CHECK(open_doc(ctx, &doc, &root, ASN1_TAG_UNIVERSAL, 6, 0) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_oid(root, "2.5.4.3") == ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, oid_bytes,
                                    sizeof(oid_bytes)));
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        asn1_doc_destroy(doc);

        ASN1_TEST_CHECK(open_doc(ctx, &doc, &root, ASN1_TAG_UNIVERSAL, 12, 0) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_utf8(root, "\xE4\xB8\xAD", 3) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, utf8_bytes,
                                    sizeof(utf8_bytes)));
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        asn1_doc_destroy(doc);
    }

    {
        /* UTCTime：13 字节内容原样写出。 */
        static const char text[] = "990101000000Z";
        static const uint8_t expected[] = {0x17, 0x0D, 0x39, 0x39, 0x30, 0x31,
                                           0x30, 0x31, 0x30, 0x30, 0x30, 0x30,
                                           0x30, 0x30, 0x5A};
        asn1_node_t *root = NULL;
        ASN1_TEST_CHECK(open_doc(ctx, &doc, &root, ASN1_TAG_UNIVERSAL, 23, 0) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_content(
                            root, (const uint8_t *)text, sizeof(text) - 1) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, expected,
                                    sizeof(expected)));
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        asn1_doc_destroy(doc);
    }

    /* ---------- 嵌套与 SET 排序 ---------- */
    {
        /* SET 子元素按标签升序：文档顺序 INTEGER(2) 先、BOOLEAN(1) 后。 */
        static const uint8_t expected[] = {0x31, 0x06, 0x01, 0x01,
                                           0xFF, 0x02, 0x01, 0x05};
        asn1_node_t *root = NULL;
        asn1_node_t *child = NULL;
        ASN1_TEST_CHECK(open_doc(ctx, &doc, &root, ASN1_TAG_UNIVERSAL, 17, 1) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(add_child(doc, root, ASN1_TAG_UNIVERSAL, 2, 0,
                                  &child) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_int64(child, 5) == ASN1_OK);
        ASN1_TEST_CHECK(add_child(doc, root, ASN1_TAG_UNIVERSAL, 1, 0,
                                  &child) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_bool(child, 1) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, expected,
                                    sizeof(expected)));
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        asn1_doc_destroy(doc);
    }

    {
        /* SET OF 同标签元素按编码字节字典序。 */
        static const uint8_t expected[] = {
            0x31, 0x09, 0x04, 0x01, 0x61, 0x04, 0x01,
            0x62, 0x04, 0x01, 0x63};
        static const uint8_t value_b[] = {0x62};
        static const uint8_t value_a[] = {0x61};
        static const uint8_t value_c[] = {0x63};
        asn1_node_t *root = NULL;
        asn1_node_t *child = NULL;
        ASN1_TEST_CHECK(open_doc(ctx, &doc, &root, ASN1_TAG_UNIVERSAL, 17, 1) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(add_child(doc, root, ASN1_TAG_UNIVERSAL, 4, 0,
                                  &child) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_content(child, value_b, 1) == ASN1_OK);
        ASN1_TEST_CHECK(add_child(doc, root, ASN1_TAG_UNIVERSAL, 4, 0,
                                  &child) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_content(child, value_a, 1) == ASN1_OK);
        ASN1_TEST_CHECK(add_child(doc, root, ASN1_TAG_UNIVERSAL, 4, 0,
                                  &child) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_content(child, value_c, 1) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, expected,
                                    sizeof(expected)));
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        asn1_doc_destroy(doc);
    }

    {
        /* 两层嵌套 SEQUENCE，且高标签号（context 40）按多字节标签写出。 */
        static const uint8_t expected[] = {0x30, 0x08, 0x30, 0x03, 0x02, 0x01,
                                           0x05, 0x9F, 0x28, 0x00};
        asn1_node_t *root = NULL;
        asn1_node_t *inner = NULL;
        asn1_node_t *leaf = NULL;
        ASN1_TEST_CHECK(open_doc(ctx, &doc, &root, ASN1_TAG_UNIVERSAL, 16, 1) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(add_child(doc, root, ASN1_TAG_UNIVERSAL, 16, 1,
                                  &inner) == ASN1_OK);
        ASN1_TEST_CHECK(add_child(doc, inner, ASN1_TAG_UNIVERSAL, 2, 0,
                                  &leaf) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_int64(leaf, 5) == ASN1_OK);
        ASN1_TEST_CHECK(add_child(doc, root, ASN1_TAG_CONTEXT, 40, 0,
                                  &leaf) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_content(leaf, NULL, 0) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(bytes_equal(buf.data, buf.size, expected,
                                    sizeof(expected)));
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        asn1_doc_destroy(doc);
    }

    /* ---------- writer 出口 ---------- */
    {
        writer_state_t state;
        memset(&state, 0, sizeof(state));
        state.result = ASN1_OK;
        asn1_writer_t writer;
        writer.struct_size = sizeof(asn1_writer_t);
        writer.user = &state;
        writer.write = capture_write;

        asn1_node_t *root = NULL;
        ASN1_TEST_CHECK(open_doc(ctx, &doc, &root, ASN1_TAG_UNIVERSAL, 2, 0) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_int64(root, 5) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_encode_writer(ctx, doc, NULL, &writer) == ASN1_OK);
        ASN1_TEST_CHECK(state.calls == 1);
        ASN1_TEST_CHECK(state.size == 3);
        ASN1_TEST_CHECK(state.bytes[0] == 0x02 && state.bytes[1] == 0x01 &&
                        state.bytes[2] == 0x05);
        asn1_doc_destroy(doc);
    }

    {
        /* writer 失败：包装为 IO_WRITE，原始码进 callback_code。 */
        writer_state_t state;
        memset(&state, 0, sizeof(state));
        state.result = (asn1_err_t)7;
        asn1_writer_t writer;
        writer.struct_size = sizeof(asn1_writer_t);
        writer.user = &state;
        writer.write = capture_write;

        asn1_node_t *root = NULL;
        ASN1_TEST_CHECK(open_doc(ctx, &doc, &root, ASN1_TAG_UNIVERSAL, 2, 0) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_int64(root, 5) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_encode_writer(ctx, doc, NULL, &writer) ==
                        ASN1_E_IO_WRITE);
        asn1_error_info_t info;
        info.struct_size = sizeof(info);
        ASN1_TEST_CHECK(asn1_ctx_get_error(ctx, &info) == ASN1_OK);
        ASN1_TEST_CHECK(info.code == ASN1_E_IO_WRITE);
        ASN1_TEST_CHECK(info.callback_code == 7);
        /* 单次回调失败：未确认接收任何字节，offset 固定记 0。 */
        ASN1_TEST_CHECK(info.offset == 0);
        ASN1_TEST_CHECK(state.calls == 1);
        asn1_doc_destroy(doc);
    }

    {
        /* writer 结构尺寸错误 / 空 writer / 空回调。 */
        writer_state_t state;
        memset(&state, 0, sizeof(state));
        asn1_writer_t writer;
        writer.struct_size = 0;
        writer.user = &state;
        writer.write = capture_write;
        asn1_node_t *root = NULL;
        ASN1_TEST_CHECK(open_doc(ctx, &doc, &root, ASN1_TAG_UNIVERSAL, 2, 0) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_int64(root, 5) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_encode_writer(ctx, doc, NULL, &writer) ==
                        ASN1_E_INVALID_CONFIG);
        ASN1_TEST_CHECK(asn1_encode_writer(ctx, doc, NULL, NULL) ==
                        ASN1_E_INVALID_ARG);
        writer.struct_size = sizeof(asn1_writer_t);
        writer.write = NULL;
        ASN1_TEST_CHECK(asn1_encode_writer(ctx, doc, NULL, &writer) ==
                        ASN1_E_INVALID_ARG);
        asn1_doc_destroy(doc);
    }

    /* ---------- 参数与选项校验 ---------- */
    {
        asn1_node_t *root = NULL;
        ASN1_TEST_CHECK(open_doc(ctx, &doc, &root, ASN1_TAG_UNIVERSAL, 2, 0) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_int64(root, 5) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);

        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, NULL) ==
                        ASN1_E_INVALID_ARG);
        ASN1_TEST_CHECK(asn1_encode_buffer(NULL, doc, NULL, &buf) ==
                        ASN1_E_INVALID_ARG);
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, NULL, NULL, &buf) ==
                        ASN1_E_INVALID_ARG);

        asn1_encode_options_init(&options);
        options.struct_size = 0;
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &options, &buf) ==
                        ASN1_E_INVALID_CONFIG);
        asn1_encode_options_init(&options);
        options.reserved[0] = 1;
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &options, &buf) ==
                        ASN1_E_INVALID_CONFIG);
        asn1_encode_options_init(&options);
        options.flags = 1;
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &options, &buf) ==
                        ASN1_E_INVALID_CONFIG);
        asn1_encode_options_init(&options);
        options.encoding = ASN1_ENCODING_BER;
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &options, &buf) ==
                        ASN1_E_UNSUPPORTED_ENCODING);
        asn1_encode_options_init(&options);
        options.encoding = ASN1_ENCODING_CER;
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &options, &buf) ==
                        ASN1_E_UNSUPPORTED_ENCODING);
        asn1_encode_options_init(&options);
        options.encoding = ASN1_ENCODING_NONE;
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &options, &buf) ==
                        ASN1_E_UNSUPPORTED_ENCODING);

        /* 未封存 schema 明确拒绝；已封存但没有根类型同样拒绝。 */
        asn1_schema_t *schema = NULL;
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        asn1_encode_options_init(&options);
        options.schema = schema;
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &options, &buf) ==
                        ASN1_E_INVALID_STATE);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &options, &buf) ==
                        ASN1_E_INVALID_STATE);
        ASN1_TEST_CHECK(buf.data == NULL && buf.size == 0);
        asn1_schema_destroy(schema);

        /* 其他上下文的文档不可编码。 */
        asn1_ctx_config_t other_config;
        asn1_ctx_config_init(&other_config);
        asn1_ctx_t *other = NULL;
        ASN1_TEST_CHECK(asn1_ctx_create(&other_config, &other) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_encode_buffer(other, doc, NULL, &buf) ==
                        ASN1_E_INVALID_ARG);
        ASN1_TEST_CHECK(asn1_encode_writer(other, doc, NULL, NULL) ==
                        ASN1_E_INVALID_ARG);
        asn1_ctx_destroy(other);

        asn1_doc_destroy(doc);
    }

    /* ---------- 输出预算 ---------- */
    {
        asn1_ctx_config_t small_config;
        asn1_ctx_config_init(&small_config);
        small_config.max_output_bytes = 5;
        asn1_ctx_t *small = NULL;
        ASN1_TEST_CHECK(asn1_ctx_create(&small_config, &small) == ASN1_OK);

        /* 恰好 5 字节：30 03 02 01 05。 */
        asn1_node_t *root = NULL;
        asn1_node_t *leaf = NULL;
        ASN1_TEST_CHECK(open_doc(small, &doc, &root, ASN1_TAG_UNIVERSAL, 16,
                                 1) == ASN1_OK);
        ASN1_TEST_CHECK(add_child(doc, root, ASN1_TAG_UNIVERSAL, 2, 0,
                                  &leaf) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_int64(leaf, 5) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_encode_buffer(small, doc, NULL, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(buf.size == 5);
        ASN1_TEST_CHECK(asn1_buf_release(small, &buf) == ASN1_OK);
        asn1_doc_destroy(doc);

        /* 两个子节点：8 字节，超过 5 字节预算。 */
        ASN1_TEST_CHECK(open_doc(small, &doc, &root, ASN1_TAG_UNIVERSAL, 16,
                                 1) == ASN1_OK);
        ASN1_TEST_CHECK(add_child(doc, root, ASN1_TAG_UNIVERSAL, 2, 0,
                                  &leaf) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_int64(leaf, 5) == ASN1_OK);
        ASN1_TEST_CHECK(add_child(doc, root, ASN1_TAG_UNIVERSAL, 2, 0,
                                  &leaf) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_int64(leaf, 6) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_encode_buffer(small, doc, NULL, &buf) ==
                        ASN1_E_OUTPUT_LIMIT);
        ASN1_TEST_CHECK(buf.data == NULL && buf.size == 0 && buf.capacity == 0);
        asn1_error_info_t info;
        info.struct_size = sizeof(info);
        ASN1_TEST_CHECK(asn1_ctx_get_error(small, &info) == ASN1_OK);
        ASN1_TEST_CHECK(info.code == ASN1_E_OUTPUT_LIMIT);
        asn1_doc_destroy(doc);

        asn1_ctx_destroy(small);
    }

    /* ---------- 输出缓冲所有权 ---------- */
    {
        asn1_node_t *root = NULL;
        ASN1_TEST_CHECK(open_doc(ctx, &doc, &root, ASN1_TAG_UNIVERSAL, 2, 0) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_node_set_int64(root, 5) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, NULL, &buf) == ASN1_OK);
        asn1_doc_destroy(doc);

        /* 跨上下文释放：返回 INVALID_ARG 且不修改缓冲。 */
        asn1_ctx_config_t other_config;
        asn1_ctx_config_init(&other_config);
        asn1_ctx_t *other = NULL;
        ASN1_TEST_CHECK(asn1_ctx_create(&other_config, &other) == ASN1_OK);
        uint8_t *data_before = buf.data;
        size_t size_before = buf.size;
        size_t capacity_before = buf.capacity;
        ASN1_TEST_CHECK(asn1_buf_release(other, &buf) == ASN1_E_INVALID_ARG);
        ASN1_TEST_CHECK(buf.data == data_before);
        ASN1_TEST_CHECK(buf.size == size_before);
        ASN1_TEST_CHECK(buf.capacity == capacity_before);
        ASN1_TEST_CHECK(asn1_buf_release(NULL, &buf) == ASN1_E_INVALID_ARG);
        asn1_ctx_destroy(other);

        /* 正确上下文释放后置零；再次释放为空操作。 */
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(buf.data == NULL && buf.size == 0 && buf.capacity == 0);
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_buf_release(ctx, NULL) == ASN1_OK);
    }

    asn1_ctx_destroy(ctx);
    return 0;
}
