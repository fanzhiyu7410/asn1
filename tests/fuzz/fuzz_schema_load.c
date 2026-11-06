/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * libFuzzer harness：asn1_schema_load 二进制描述表加载。
 * 任意字节都可作为“表”输入，是最主要的攻击面；返回错误码属正常行为。
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

    asn1_schema_table_t table;
    asn1_schema_t *schema = NULL;

    table.struct_size = sizeof(table);
    table.data = data;
    table.size = size;
    table.format_version = 1u << 16;
    table.reserved = 0;

    (void)asn1_schema_load(ctx, &table, &schema);
    if (schema != NULL) {
        asn1_schema_destroy(schema);
    }

    asn1_ctx_destroy(ctx);
    return 0;
}