/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * libFuzzer harness：reader 路径（asn1_decode_reader 与
 * asn1_decode_reader_with_schema）。内存 reader 按块供应，覆盖分段/预读/
 * 回调包装；with_schema 同时覆盖未知字段与 ANY 绑定。
 */
#include <asn1/asn1.h>

#include <stddef.h>
#include <stdint.h>

#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    asn1_ctx_t *ctx = fuzz_ctx_create();
    if (ctx == NULL) {
        return 0;
    }

    fuzz_mem_reader_t mem = { data, size, 0 };
    asn1_reader_t reader;
    reader.struct_size = sizeof(reader);
    reader.user = &mem;
    reader.read = fuzz_mem_read;

    asn1_decode_options_t options;
    asn1_decode_options_init(&options);
    options.struct_size = sizeof(options);
    options.encoding = ASN1_ENCODING_BER;

    asn1_doc_t *doc = NULL;
    size_t consumed = 0;
    (void)asn1_decode_reader(ctx, &reader, &options, &doc, &consumed);
    if (doc != NULL) {
        fuzz_walk(asn1_doc_root(doc));
        asn1_doc_destroy(doc);
    }

    /* reader + schema：用最小手工表跑一遍未知字段/ANY 绑定。 */
    asn1_schema_t *schema = fuzz_min_schema_create(ctx);
    if (schema != NULL) {
        mem.pos = 0;
        doc = NULL;
        (void)asn1_decode_reader_with_schema(ctx, &reader, schema, &options,
                                             &doc, &consumed);
        if (doc != NULL) {
            fuzz_walk(asn1_doc_root(doc));
            asn1_doc_destroy(doc);
        }
        asn1_schema_destroy(schema);
    }

    asn1_ctx_destroy(ctx);
    return 0;
}