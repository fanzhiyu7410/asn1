/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * 上下文与内存：配置校验、静态池、尺寸查询与错误状态。
 */
#include <asn1/asn1.h>

#include <stddef.h>

#include "check.h"

/* 提供 max_align_t 级别对齐的静态池存储。 */
static union {
    long double ld;
    double d;
    void *p;
    unsigned long long u;
    unsigned char bytes[16384];
} pool_storage;

int main(void)
{
    asn1_ctx_config_t config;
    asn1_ctx_config_init(&config);
    ASN1_TEST_CHECK(config.struct_size == sizeof(config));
    ASN1_TEST_CHECK(config.allocator == NULL);
    ASN1_TEST_CHECK(config.static_pool == NULL);
    ASN1_TEST_CHECK(config.max_depth == 0);
    ASN1_TEST_CHECK(config.max_warnings == 0);

    size_t required = 0;
    ASN1_TEST_CHECK(asn1_ctx_size_for_config(&config, &required) == ASN1_OK);
    ASN1_TEST_CHECK(required > 0);
    size_t rejected_size = 0;
    ASN1_TEST_CHECK(asn1_ctx_size_for_config(NULL, &rejected_size) ==
                    ASN1_E_INVALID_ARG);

    asn1_ctx_t *ctx = NULL;
    ASN1_TEST_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_OK);
    ASN1_TEST_CHECK(ctx != NULL);

    asn1_error_info_t info;
    info.struct_size = sizeof(info);
    ASN1_TEST_CHECK(asn1_ctx_get_error(ctx, &info) == ASN1_OK);
    ASN1_TEST_CHECK(info.code == ASN1_OK);
    ASN1_TEST_CHECK(info.message == NULL);
    ASN1_TEST_CHECK(info.callback_code == 0);
    ASN1_TEST_CHECK(info.offset == SIZE_MAX);
    ASN1_TEST_CHECK(info.depth == 0);
    ASN1_TEST_CHECK(info.path == NULL);

    asn1_ctx_destroy(ctx);
    asn1_ctx_destroy(NULL);

    /* struct_size 错误与预留字段非零。 */
    ASN1_TEST_CHECK(asn1_ctx_create(NULL, &ctx) == ASN1_E_INVALID_ARG);
    config.struct_size = 0;
    ASN1_TEST_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_E_INVALID_CONFIG);
    asn1_ctx_config_init(&config);
    config.reserved_flags = 1;
    ASN1_TEST_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_E_INVALID_CONFIG);
    asn1_ctx_config_init(&config);
    config.reserved[0] = 1;
    ASN1_TEST_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_E_INVALID_CONFIG);

    /* 静态池：正常创建与销毁。 */
    asn1_ctx_config_init(&config);
    config.static_pool = (void *)&pool_storage;
    config.static_pool_size = sizeof(pool_storage);
    ASN1_TEST_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_OK);

    asn1_doc_t *doc = NULL;
    ASN1_TEST_CHECK(asn1_doc_create(ctx, &doc) == ASN1_OK);
    asn1_node_t *root = NULL;
    ASN1_TEST_CHECK(asn1_node_create(doc, NULL, ASN1_TAG_UNIVERSAL, 16, 1,
                                     &root) == ASN1_OK);
    asn1_node_t *child = NULL;
    ASN1_TEST_CHECK(asn1_node_create(doc, root, ASN1_TAG_UNIVERSAL, 2, 0,
                                     &child) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_node_set_int64(child, 7) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_doc_seal(doc) == ASN1_OK);
    asn1_doc_destroy(doc);
    asn1_ctx_destroy(ctx);

    /* 静态池过小：上下文创建失败。 */
    asn1_ctx_config_init(&config);
    config.static_pool = (void *)&pool_storage;
    config.static_pool_size = required - 1;
    ASN1_TEST_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_E_INVALID_CONFIG);

    /* 池恰好容纳上下文：上下文级分配返回耗尽错误。 */
    config.static_pool_size = required;
    ASN1_TEST_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_OK);
    doc = NULL;
    ASN1_TEST_CHECK(asn1_doc_create(ctx, &doc) ==
                    ASN1_E_STATIC_POOL_EXHAUSTED);
    ASN1_TEST_CHECK(doc == NULL);
    ASN1_TEST_CHECK(asn1_ctx_get_error(ctx, &info) == ASN1_OK);
    ASN1_TEST_CHECK(info.code == ASN1_E_STATIC_POOL_EXHAUSTED);
    asn1_ctx_destroy(ctx);

    /* 地址非空但尺寸为 0、地址为空但尺寸非 0。 */
    asn1_ctx_config_init(&config);
    config.static_pool = (void *)&pool_storage;
    config.static_pool_size = 0;
    ASN1_TEST_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_E_INVALID_CONFIG);
    asn1_ctx_config_init(&config);
    config.static_pool_size = sizeof(pool_storage);
    ASN1_TEST_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_E_INVALID_CONFIG);

    return 0;
}
