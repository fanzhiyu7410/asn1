/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * reader 解码路径：分段拉取、段边界切断 TLV、IO 回调失败包装、
 * consumed 语义、尾随判定、BER 不定长，以及 schema 感知 reader。
 */
#include <asn1/asn1.h>

#include <stddef.h>
#include <string.h>

#include "check.h"

/* ---------- 分段 reader ---------- */

typedef struct {
    const uint8_t *data;
    size_t size;
    size_t pos;
    size_t chunk;          /* 每次最多返回的字节数；0 表示一次读满 */
    asn1_err_t fail_code;  /* 非 ASN1_OK 时在该次回调返回该码 */
    size_t fail_at;        /* 第几次回调失败（从 1 开始） */
    size_t calls;
} stream_t;

static void stream_init(stream_t *stream, const uint8_t *data, size_t size,
                        size_t chunk)
{
    memset(stream, 0, sizeof(*stream));
    stream->data = data;
    stream->size = size;
    stream->chunk = chunk;
}

static asn1_err_t stream_read(void *user, uint8_t *out, size_t capacity,
                              size_t *out_size)
{
    stream_t *stream = (stream_t *)user;
    ++stream->calls;
    if (stream->fail_code != ASN1_OK && stream->calls == stream->fail_at) {
        *out_size = 0;
        return stream->fail_code;
    }
    if (stream->pos >= stream->size) {
        *out_size = 0;
        return ASN1_OK;
    }
    size_t take = stream->size - stream->pos;
    if (stream->chunk != 0 && take > stream->chunk) {
        take = stream->chunk;
    }
    if (take > capacity) {
        take = capacity;
    }
    memcpy(out, stream->data + stream->pos, take);
    stream->pos += take;
    *out_size = take;
    return ASN1_OK;
}

static void reader_init(asn1_reader_t *reader, stream_t *stream)
{
    memset(reader, 0, sizeof(*reader));
    reader->struct_size = sizeof(asn1_reader_t);
    reader->user = stream;
    reader->read = stream_read;
}

static int bytes_equal(const uint8_t *actual, size_t actual_size,
                       const uint8_t *expected, size_t expected_size)
{
    if (actual_size != expected_size) {
        return 0;
    }
    return memcmp(actual, expected, expected_size) == 0;
}

static asn1_type_desc_t make_type(const char *name, asn1_type_kind_t kind,
                                  uint32_t tag_number)
{
    asn1_type_desc_t desc;
    memset(&desc, 0, sizeof(desc));
    desc.struct_size = sizeof(desc);
    desc.name = name;
    desc.kind = kind;
    desc.tag_class = ASN1_TAG_UNIVERSAL;
    desc.tag_number = tag_number;
    desc.tag_mode = ASN1_TAG_MODE_DEFAULT;
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

/* 通用路径的分段解码辅助。 */
static int decode_segments(asn1_ctx_t *ctx, const uint8_t *data, size_t size,
                           size_t chunk, size_t expected_consumed)
{
    stream_t stream;
    asn1_reader_t reader;
    stream_init(&stream, data, size, chunk);
    reader_init(&reader, &stream);
    asn1_doc_t *doc = NULL;
    size_t consumed = 0;
    ASN1_TEST_CHECK(asn1_decode_reader(ctx, &reader, NULL, &doc, &consumed) ==
                    ASN1_OK);
    ASN1_TEST_CHECK(doc != NULL);
    ASN1_TEST_CHECK(consumed == expected_consumed);
    ASN1_TEST_CHECK(asn1_doc_root(doc) != NULL);
    ASN1_TEST_CHECK(asn1_node_child_count(asn1_doc_root(doc)) == 2);
    asn1_doc_destroy(doc);
    return 0;
}

/* ---------- 用例 ---------- */

int main(void)
{
    asn1_ctx_t *ctx = NULL;
    asn1_ctx_config_t config;
    asn1_ctx_config_init(&config);
    ASN1_TEST_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_OK);

    /* SEQUENCE { INTEGER 5, OCTET STRING "hi" }。 */
    static const uint8_t kSeq[9] = {0x30, 0x07, 0x02, 0x01, 0x05,
                                    0x04, 0x02, 0x68, 0x69};

    /* 1. 多段流与段边界切断 TLV。 */
    ASN1_TEST_CHECK(decode_segments(ctx, kSeq, sizeof(kSeq), 1,
                                    sizeof(kSeq)) == 0);
    ASN1_TEST_CHECK(decode_segments(ctx, kSeq, sizeof(kSeq), 2,
                                    sizeof(kSeq)) == 0);
    ASN1_TEST_CHECK(decode_segments(ctx, kSeq, sizeof(kSeq), 4,
                                    sizeof(kSeq)) == 0);

    /* 2. 回调中途失败：包装为 IO_READ，原始码进 callback_code。 */
    {
        stream_t stream;
        asn1_reader_t reader;
        stream_init(&stream, kSeq, sizeof(kSeq), 2);
        reader_init(&reader, &stream);
        stream.fail_code = ASN1_E_IO_WRITE;
        stream.fail_at = 3;
        asn1_doc_t *doc = NULL;
        size_t consumed = 123;
        ASN1_TEST_CHECK(asn1_decode_reader(ctx, &reader, NULL, &doc,
                                           &consumed) == ASN1_E_IO_READ);
        ASN1_TEST_CHECK(doc == NULL);
        ASN1_TEST_CHECK(consumed == 123);
        asn1_error_info_t info;
        memset(&info, 0, sizeof(info));
        info.struct_size = sizeof(info);
        ASN1_TEST_CHECK(asn1_ctx_get_error(ctx, &info) == ASN1_OK);
        ASN1_TEST_CHECK(info.code == ASN1_E_IO_READ);
        ASN1_TEST_CHECK(info.callback_code == ASN1_E_IO_WRITE);
        ASN1_TEST_CHECK(info.offset == 4);
    }

    /* 3. 尾随判定与 ALLOW_TRAILING。 */
    {
        static const uint8_t kTrailing[11] = {0x30, 0x07, 0x02, 0x01, 0x05,
                                              0x04, 0x02, 0x68, 0x69,
                                              0x05, 0x00};
        stream_t stream;
        asn1_reader_t reader;
        asn1_doc_t *doc = NULL;
        size_t consumed = 123;
        stream_init(&stream, kTrailing, sizeof(kTrailing), 3);
        reader_init(&reader, &stream);
        ASN1_TEST_CHECK(asn1_decode_reader(ctx, &reader, NULL, &doc,
                                           &consumed) ==
                        ASN1_E_TRAILING_DATA);
        ASN1_TEST_CHECK(doc == NULL);
        ASN1_TEST_CHECK(consumed == 123);

        stream_init(&stream, kTrailing, sizeof(kTrailing), 3);
        reader_init(&reader, &stream);
        asn1_decode_options_t options;
        asn1_decode_options_init(&options);
        options.flags = ASN1_DECODE_ALLOW_TRAILING;
        ASN1_TEST_CHECK(asn1_decode_reader(ctx, &reader, &options, &doc,
                                           &consumed) == ASN1_OK);
        ASN1_TEST_CHECK(consumed == sizeof(kTrailing));
        asn1_doc_destroy(doc);
    }

    /* 4. BER 不定长在 reader 路径同样支持。 */
    {
        static const uint8_t kIndefinite[7] = {0x30, 0x80, 0x02,
                                               0x01, 0x05, 0x00, 0x00};
        stream_t stream;
        asn1_reader_t reader;
        stream_init(&stream, kIndefinite, sizeof(kIndefinite), 1);
        reader_init(&reader, &stream);
        asn1_doc_t *doc = NULL;
        size_t consumed = 0;
        ASN1_TEST_CHECK(asn1_decode_reader(ctx, &reader, NULL, &doc,
                                           &consumed) == ASN1_OK);
        ASN1_TEST_CHECK(consumed == sizeof(kIndefinite));
        ASN1_TEST_CHECK(asn1_node_child_count(asn1_doc_root(doc)) == 1);
        asn1_doc_destroy(doc);
    }

    /* 5. 空流与非法 reader 配置。 */
    {
        stream_t stream;
        asn1_reader_t reader;
        asn1_doc_t *doc = NULL;
        size_t consumed = 123;
        stream_init(&stream, kSeq, 0, 1);
        reader_init(&reader, &stream);
        ASN1_TEST_CHECK(asn1_decode_reader(ctx, &reader, NULL, &doc,
                                           &consumed) == ASN1_E_TRUNCATED);
        ASN1_TEST_CHECK(consumed == 123);

        memset(&reader, 0, sizeof(reader));
        reader.struct_size = sizeof(asn1_reader_t);
        ASN1_TEST_CHECK(asn1_decode_reader(ctx, &reader, NULL, &doc,
                                           &consumed) ==
                        ASN1_E_INVALID_CONFIG);
    }

    /* 6. COPY_INPUT 与 reader 同设：按忽略处理。 */
    {
        stream_t stream;
        asn1_reader_t reader;
        stream_init(&stream, kSeq, sizeof(kSeq), 2);
        reader_init(&reader, &stream);
        asn1_decode_options_t options;
        asn1_decode_options_init(&options);
        options.flags = ASN1_DECODE_COPY_INPUT;
        asn1_doc_t *doc = NULL;
        size_t consumed = 0;
        ASN1_TEST_CHECK(asn1_decode_reader(ctx, &reader, &options, &doc,
                                           &consumed) == ASN1_OK);
        ASN1_TEST_CHECK(consumed == sizeof(kSeq));
        asn1_doc_destroy(doc);
    }

    /* 7. schema 感知 reader：绑定、严格未知字段、consumed。 */
    {
        asn1_schema_t *schema = NULL;
        uint32_t intId = 0;
        uint32_t seqId = 0;
        asn1_type_desc_t intType = make_type("Int", ASN1_TYPE_KIND_SIMPLE, 2);
        asn1_type_desc_t seqType =
            make_type("Seq", ASN1_TYPE_KIND_SEQUENCE, 16);
        ASN1_TEST_CHECK(asn1_schema_create(ctx, ASN1_TAG_MODE_DEFAULT,
                                           &schema) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &intType, &intId) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_add_type(schema, &seqType, &seqId) ==
                        ASN1_OK);
        asn1_field_desc_t aField = make_field("a", intId);
        ASN1_TEST_CHECK(asn1_schema_add_field(schema, seqId, &aField) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_set_root(schema, seqId) == ASN1_OK);
        ASN1_TEST_CHECK(asn1_schema_seal(schema) == ASN1_OK);

        stream_t stream;
        asn1_reader_t reader;
        asn1_doc_t *doc = NULL;
        size_t consumed = 0;
        stream_init(&stream, kSeq, sizeof(kSeq), 2);
        reader_init(&reader, &stream);
        ASN1_TEST_CHECK(asn1_decode_reader_with_schema(ctx, &reader, schema,
                                                       NULL, &doc,
                                                       &consumed) == ASN1_OK);
        ASN1_TEST_CHECK(consumed == sizeof(kSeq));
        const asn1_node_t *root = asn1_doc_root(doc);
        ASN1_TEST_CHECK(root != NULL);
        ASN1_TEST_CHECK(asn1_node_child_count(root) == 2);
        const asn1_node_t *child = asn1_node_child_at(root, 0);
        ASN1_TEST_CHECK(child != NULL);
        ASN1_TEST_CHECK(asn1_node_field_name(child) != NULL);
        ASN1_TEST_CHECK(strcmp(asn1_node_field_name(child), "a") == 0);
        asn1_doc_destroy(doc);

        /* 严格路径拒绝未知字段。 */
        static const uint8_t kUnknown[8] = {0x30, 0x06, 0x02, 0x01,
                                            0x05, 0x04, 0x01, 0x00};
        stream_init(&stream, kUnknown, sizeof(kUnknown), 2);
        reader_init(&reader, &stream);
        doc = NULL;
        consumed = 123;
        asn1_decode_options_t options;
        asn1_decode_options_init(&options);
        options.flags = ASN1_DECODE_STRICT_SCHEMA;
        ASN1_TEST_CHECK(asn1_decode_reader_with_schema(ctx, &reader, schema,
                                                       &options, &doc,
                                                       &consumed) ==
                        ASN1_E_SCHEMA_FIELD);
        ASN1_TEST_CHECK(doc == NULL);
        ASN1_TEST_CHECK(consumed == 123);

        /* COPY_INPUT 与 reader 同设：忽略。 */
        stream_init(&stream, kSeq, sizeof(kSeq), 1);
        reader_init(&reader, &stream);
        asn1_decode_options_init(&options);
        options.flags = ASN1_DECODE_COPY_INPUT;
        doc = NULL;
        consumed = 0;
        ASN1_TEST_CHECK(asn1_decode_reader_with_schema(ctx, &reader, schema,
                                                       &options, &doc,
                                                       &consumed) == ASN1_OK);
        ASN1_TEST_CHECK(consumed == sizeof(kSeq));
        asn1_doc_destroy(doc);

        asn1_schema_destroy(schema);
    }

    asn1_ctx_destroy(ctx);
    return 0;
}
