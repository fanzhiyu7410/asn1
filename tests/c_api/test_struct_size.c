/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * 公共结构体 struct_size ABI 守卫。
 *
 * 对 8 个带 struct_size 的公共结构体，分别传入 0、sizeof-1、sizeof 与
 * sizeof+64：前两者与超大值必须被参数校验拒绝，只有精确的 sizeof 被接受。
 * 这能锁住“布局变化时调用方与库不一致”的故障边界，而不是依赖某个字段的
 * 偶然布局。
 */
#include <asn1/asn1.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "check.h"

static const uint8_t kBasic[] = {0x30, 0x03, 0x02, 0x01, 0x05};
static const uint8_t kUtcTime[] = {0x17, 0x0D, '2', '5', '0', '1', '0',
                                   '1', '0', '0', '0', '0', '0', '0', 'Z'};

struct read_state {
    const uint8_t *data;
    size_t size;
    size_t pos;
};

static asn1_err_t read_chunk(void *user, uint8_t *dst, size_t capacity,
                             size_t *out_size)
{
    struct read_state *state = (struct read_state *)user;
    const size_t remaining = state->size - state->pos;
    const size_t n = remaining < capacity ? remaining : capacity;
    if (n != 0) {
        memcpy(dst, state->data + state->pos, n);
    }
    state->pos += n;
    *out_size = n;
    return ASN1_OK;
}

struct write_state {
    size_t calls;
    size_t bytes;
};

static asn1_err_t write_chunk(void *user, const uint8_t *data, size_t size)
{
    struct write_state *state = (struct write_state *)user;
    (void)data;
    state->calls += 1;
    state->bytes += size;
    return ASN1_OK;
}

int main(void)
{
    asn1_ctx_config_t config;
    asn1_ctx_config_init(&config);

    /* 1. asn1_ctx_config_t：输入结构体。 */
    {
        static const size_t kBadSizes[] = {
            0, sizeof(asn1_ctx_config_t) - 1,
            sizeof(asn1_ctx_config_t) + 64};
        size_t i;
        for (i = 0; i < sizeof(kBadSizes) / sizeof(kBadSizes[0]); ++i) {
            asn1_ctx_config_t bad;
            asn1_ctx_t *out = NULL;
            asn1_ctx_config_init(&bad);
            bad.struct_size = kBadSizes[i];
            ASN1_TEST_CHECK(asn1_ctx_create(&bad, &out) ==
                            ASN1_E_INVALID_CONFIG);
            ASN1_TEST_CHECK(out == NULL);
        }
    }

    asn1_ctx_t *ctx = NULL;
    ASN1_TEST_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_OK);
    ASN1_TEST_CHECK(ctx != NULL);

    /* 2. asn1_decode_options_t：输入结构体。 */
    {
        static const size_t kBadSizes[] = {
            0, sizeof(asn1_decode_options_t) - 1,
            sizeof(asn1_decode_options_t) + 64};
        size_t i;
        for (i = 0; i < sizeof(kBadSizes) / sizeof(kBadSizes[0]); ++i) {
            asn1_decode_options_t options;
            asn1_doc_t *doc = NULL;
            size_t consumed = 0;
            asn1_decode_options_init(&options);
            options.struct_size = kBadSizes[i];
            ASN1_TEST_CHECK(asn1_decode_buffer(ctx, kBasic, sizeof(kBasic),
                                               &options, &doc,
                                               &consumed) ==
                            ASN1_E_INVALID_CONFIG);
            ASN1_TEST_CHECK(doc == NULL);
        }
    }

    /* 3. asn1_error_info_t：输出结构体。 */
    {
        static const size_t kBadSizes[] = {
            0, sizeof(asn1_error_info_t) - 1,
            sizeof(asn1_error_info_t) + 64};
        size_t i;
        asn1_ctx_clear_error(ctx);
        for (i = 0; i < sizeof(kBadSizes) / sizeof(kBadSizes[0]); ++i) {
            asn1_error_info_t info;
            memset(&info, 0, sizeof(info));
            info.struct_size = kBadSizes[i];
            ASN1_TEST_CHECK(asn1_ctx_get_error(ctx, &info) ==
                            ASN1_E_INVALID_CONFIG);
        }
        asn1_error_info_t info;
        memset(&info, 0, sizeof(info));
        info.struct_size = sizeof(info);
        ASN1_TEST_CHECK(asn1_ctx_get_error(ctx, &info) == ASN1_OK);
    }

    /* 4. asn1_version_info_t：输出结构体。 */
    {
        static const size_t kBadSizes[] = {
            0, sizeof(asn1_version_info_t) - 1,
            sizeof(asn1_version_info_t) + 64};
        size_t i;
        for (i = 0; i < sizeof(kBadSizes) / sizeof(kBadSizes[0]); ++i) {
            asn1_version_info_t info;
            memset(&info, 0, sizeof(info));
            info.struct_size = kBadSizes[i];
            ASN1_TEST_CHECK(asn1_version(&info) == ASN1_E_INVALID_CONFIG);
        }
        asn1_version_info_t info;
        memset(&info, 0, sizeof(info));
        info.struct_size = sizeof(info);
        ASN1_TEST_CHECK(asn1_version(&info) == ASN1_OK);
        ASN1_TEST_CHECK(info.major == ASN1_VERSION_MAJOR);
        ASN1_TEST_CHECK(info.minor == ASN1_VERSION_MINOR);
        ASN1_TEST_CHECK(info.patch == ASN1_VERSION_PATCH);
        ASN1_TEST_CHECK(info.string != NULL);
    }

    /* 5. asn1_encode_options_t：输入结构体。 */
    {
        asn1_doc_t *doc = NULL;
        size_t consumed = 0;
        ASN1_TEST_CHECK(asn1_decode_buffer(ctx, kBasic, sizeof(kBasic), NULL,
                                           &doc, &consumed) == ASN1_OK);
        static const size_t kBadSizes[] = {
            0, sizeof(asn1_encode_options_t) - 1,
            sizeof(asn1_encode_options_t) + 64};
        size_t i;
        for (i = 0; i < sizeof(kBadSizes) / sizeof(kBadSizes[0]); ++i) {
            asn1_encode_options_t options;
            asn1_buf_t buf;
            asn1_encode_options_init(&options);
            options.struct_size = kBadSizes[i];
            memset(&buf, 0, sizeof(buf));
            ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &options, &buf) ==
                            ASN1_E_INVALID_CONFIG);
            ASN1_TEST_CHECK(buf.data == NULL && buf.size == 0);
        }
        asn1_encode_options_t options;
        asn1_buf_t buf;
        asn1_encode_options_init(&options);
        memset(&buf, 0, sizeof(buf));
        ASN1_TEST_CHECK(asn1_encode_buffer(ctx, doc, &options, &buf) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(buf.data != NULL && buf.size == sizeof(kBasic));
        ASN1_TEST_CHECK(asn1_buf_release(ctx, &buf) == ASN1_OK);
        asn1_doc_destroy(doc);
    }

    /* 6. asn1_writer_t：输入结构体。 */
    {
        asn1_doc_t *doc = NULL;
        size_t consumed = 0;
        ASN1_TEST_CHECK(asn1_decode_buffer(ctx, kBasic, sizeof(kBasic), NULL,
                                           &doc, &consumed) == ASN1_OK);
        static const size_t kBadSizes[] = {
            0, sizeof(asn1_writer_t) - 1, sizeof(asn1_writer_t) + 64};
        size_t i;
        for (i = 0; i < sizeof(kBadSizes) / sizeof(kBadSizes[0]); ++i) {
            asn1_writer_t writer;
            struct write_state state;
            memset(&writer, 0, sizeof(writer));
            memset(&state, 0, sizeof(state));
            writer.struct_size = kBadSizes[i];
            writer.user = &state;
            writer.write = write_chunk;
            ASN1_TEST_CHECK(asn1_encode_writer(ctx, doc, NULL, &writer) ==
                            ASN1_E_INVALID_CONFIG);
            ASN1_TEST_CHECK(state.calls == 0);
        }
        asn1_writer_t writer;
        struct write_state state;
        memset(&writer, 0, sizeof(writer));
        memset(&state, 0, sizeof(state));
        writer.struct_size = sizeof(writer);
        writer.user = &state;
        writer.write = write_chunk;
        ASN1_TEST_CHECK(asn1_encode_writer(ctx, doc, NULL, &writer) ==
                        ASN1_OK);
        ASN1_TEST_CHECK(state.calls == 1);
        ASN1_TEST_CHECK(state.bytes == sizeof(kBasic));
        asn1_doc_destroy(doc);
    }

    /* 7. asn1_reader_t：输入结构体。 */
    {
        static const size_t kBadSizes[] = {
            0, sizeof(asn1_reader_t) - 1, sizeof(asn1_reader_t) + 64};
        size_t i;
        for (i = 0; i < sizeof(kBadSizes) / sizeof(kBadSizes[0]); ++i) {
            asn1_reader_t reader;
            struct read_state state = {kBasic, sizeof(kBasic), 0};
            asn1_doc_t *doc = NULL;
            size_t consumed = 0;
            memset(&reader, 0, sizeof(reader));
            reader.struct_size = kBadSizes[i];
            reader.user = &state;
            reader.read = read_chunk;
            ASN1_TEST_CHECK(asn1_decode_reader(ctx, &reader, NULL, &doc,
                                               &consumed) ==
                            ASN1_E_INVALID_CONFIG);
            ASN1_TEST_CHECK(doc == NULL);
            ASN1_TEST_CHECK(state.pos == 0);
        }
        asn1_reader_t reader;
        struct read_state state = {kBasic, sizeof(kBasic), 0};
        asn1_doc_t *doc = NULL;
        size_t consumed = 0;
        memset(&reader, 0, sizeof(reader));
        reader.struct_size = sizeof(reader);
        reader.user = &state;
        reader.read = read_chunk;
        ASN1_TEST_CHECK(asn1_decode_reader(ctx, &reader, NULL, &doc,
                                           &consumed) == ASN1_OK);
        ASN1_TEST_CHECK(doc != NULL);
        ASN1_TEST_CHECK(consumed == sizeof(kBasic));
        asn1_doc_destroy(doc);
    }

    /* 8. asn1_time_t：输出结构体。 */
    {
        asn1_doc_t *doc = NULL;
        size_t consumed = 0;
        ASN1_TEST_CHECK(asn1_decode_buffer(ctx, kUtcTime, sizeof(kUtcTime),
                                           NULL, &doc, &consumed) == ASN1_OK);
        const asn1_node_t *root = asn1_doc_root(doc);
        static const size_t kBadSizes[] = {
            0, sizeof(asn1_time_t) - 1, sizeof(asn1_time_t) + 64};
        size_t i;
        for (i = 0; i < sizeof(kBadSizes) / sizeof(kBadSizes[0]); ++i) {
            asn1_time_t time;
            memset(&time, 0, sizeof(time));
            time.struct_size = kBadSizes[i];
            ASN1_TEST_CHECK(asn1_node_get_time(root, &time) ==
                            ASN1_E_INVALID_CONFIG);
        }
        asn1_time_t time;
        memset(&time, 0, sizeof(time));
        time.struct_size = sizeof(time);
        ASN1_TEST_CHECK(asn1_node_get_time(root, &time) == ASN1_OK);
        ASN1_TEST_CHECK(time.year == 2025);
        ASN1_TEST_CHECK(time.month == 1);
        ASN1_TEST_CHECK(time.day == 1);
        ASN1_TEST_CHECK(time.hour == 0);
        ASN1_TEST_CHECK(time.minute == 0);
        ASN1_TEST_CHECK(time.second == 0);
        asn1_doc_destroy(doc);
    }

    asn1_ctx_destroy(ctx);
    return 0;
}
