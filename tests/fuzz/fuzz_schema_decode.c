/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * libFuzzer harness：schema 感知解码（asn1_decode_buffer_with_schema）。
 * 固定 schema 各跑一遍：PKIX 表（真实 24 KB 描述表）与最小手工表。
 * PKIX schema 进程内只加载一次，跨输入复用。
 */
#include <asn1/asn1.h>
#include <pkix_schema.h>

#include <stddef.h>
#include <stdint.h>

#include "fuzz_common.h"

static asn1_ctx_t    *g_schema_ctx = NULL;
static asn1_schema_t *g_pkix_schema = NULL;
static asn1_schema_t *g_min_schema = NULL;
static int            g_init_done = 0;

static void ensure_schemas(void)
{
    asn1_schema_table_t table;
    uint32_t version = 1u << 16;

    if (g_init_done) {
        return;
    }

    g_schema_ctx = fuzz_ctx_create();
    if (g_schema_ctx == NULL) {
        g_init_done = 1;
        return;
    }

    table.struct_size = sizeof(table);
    table.data = kPKIXFlattened2009Schema;
    table.size = kPKIXFlattened2009Schema_size;
    table.format_version = version;
    table.reserved = 0;
    (void)asn1_schema_load(g_schema_ctx, &table, &g_pkix_schema);

    g_min_schema = fuzz_min_schema_create(g_schema_ctx);
    g_init_done = 1;
}

static void run_schema(asn1_ctx_t *ctx, const asn1_schema_t *schema,
                       const uint8_t *data, size_t size)
{
    asn1_decode_options_t options;
    asn1_doc_t *doc = NULL;
    size_t consumed = 0;

    asn1_decode_options_init(&options);
    options.struct_size = sizeof(options);
    options.encoding = ASN1_ENCODING_BER;

    (void)asn1_decode_buffer_with_schema(ctx, data, size, schema, &options,
                                         &doc, &consumed);
    if (doc != NULL) {
        fuzz_walk(asn1_doc_root(doc));
        asn1_doc_destroy(doc);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    asn1_ctx_t *ctx = fuzz_ctx_create();
    if (ctx == NULL) {
        return 0;
    }

    ensure_schemas();

    if (g_pkix_schema != NULL) {
        run_schema(ctx, g_pkix_schema, data, size);
    }
    if (g_min_schema != NULL) {
        run_schema(ctx, g_min_schema, data, size);
    }

    asn1_ctx_destroy(ctx);
    return 0;
}