/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * 宿主测量用例：静态池 + 打开 CMS ContentInfo 所需的最小池。
 * 二分求最小 static_pool_size，使“创建 ctx → open ContentInfo → close → 销毁”
 * 全程不返回 ASN1_E_STATIC_POOL_EXHAUSTED。
 * 同时验证池不足时 open 返回 ASN1_E_STATIC_POOL_EXHAUSTED 而不是崩溃。
 */
#include <asn1/asn1.h>
#include <asn1/cms/cms.h>

#include <stdio.h>

#include "../data/cms_rsa_attached.h"

#define MAX_POOL ((size_t)1u << 20)

static union align_pool {
    long double align_ld;
    void *align_ptr;
    unsigned char bytes[MAX_POOL];
} g_pool;

static int try_pool(size_t size, asn1_err_t *out_error)
{
    asn1_ctx_config_t config;
    asn1_ctx_t *ctx = NULL;
    asn1_cms_content_info_t *info = NULL;
    int ok = 0;

    asn1_ctx_config_init(&config);
    config.static_pool = g_pool.bytes;
    config.static_pool_size = size;

    const asn1_err_t create_err = asn1_ctx_create(&config, &ctx);
    if (create_err != ASN1_OK) {
        if (out_error != NULL) {
            *out_error = create_err;
        }
        return 0;
    }

    asn1_err_t err =
        asn1_cms_content_info_open(ctx, kCmsRsaAttached, kCmsRsaAttachedSize,
                                   &info);
    if (err == ASN1_OK && info != NULL) {
        ok = 1;
    } else if (out_error != NULL) {
        *out_error = err;
    }
    asn1_cms_content_info_close(info);
    asn1_ctx_destroy(ctx);
    return ok;
}

static size_t find_min_pool(void)
{
    size_t lo = 1;
    size_t hi = MAX_POOL;

    if (!try_pool(hi, NULL)) {
        return 0;
    }
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (try_pool(mid, NULL)) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    return lo;
}

int main(void)
{
    asn1_ctx_config_t cfg;
    size_t ctx_floor = 0;
    size_t min_pool;
    size_t exhausted_pool;
    asn1_err_t err = ASN1_OK;

    asn1_ctx_config_init(&cfg);
    (void)asn1_ctx_size_for_config(&cfg, &ctx_floor);
    min_pool = find_min_pool();

    printf("asn1_ctx_size_for_config = %zu bytes\n", ctx_floor);
    printf("min_static_pool_size(CMS ContentInfo open) = %zu bytes\n", min_pool);

    if (min_pool == 0 || min_pool > MAX_POOL) {
        fprintf(stderr, "FAIL: 未能在 %zu 字节内满足\n", MAX_POOL);
        return 1;
    }
    if (min_pool < ctx_floor) {
        fprintf(stderr, "FAIL: 最小池小于 ctx 固定开销\n");
        return 1;
    }

    /* 池刚好能创建 ctx 但不足 open：必须是明确错误，不是崩溃。 */
    exhausted_pool = ctx_floor + (min_pool - ctx_floor) / 2;
    if (exhausted_pool >= min_pool) {
        exhausted_pool = min_pool - 1;
    }
    if (try_pool(exhausted_pool, &err) ||
        err != ASN1_E_STATIC_POOL_EXHAUSTED) {
        fprintf(stderr, "FAIL: 池耗尽未失败或返回 %d，期望 %d\n", (int)err,
                (int)ASN1_E_STATIC_POOL_EXHAUSTED);
        return 1;
    }
    printf("pool exhausted at %zu bytes -> ASN1_E_STATIC_POOL_EXHAUSTED\n",
           exhausted_pool);

    /* 边界：min_pool - 1 必须失败，min_pool 必须成功。 */
    if (min_pool > ctx_floor) {
        err = ASN1_OK;
        if (try_pool(min_pool - 1, &err) ||
            err != ASN1_E_STATIC_POOL_EXHAUSTED) {
            fprintf(stderr, "FAIL: min_pool - 1 未失败或返回 %d\n", (int)err);
            return 1;
        }
        err = ASN1_OK;
        if (!try_pool(min_pool, &err)) {
            fprintf(stderr, "FAIL: min_pool 失败，返回 %d\n", (int)err);
            return 1;
        }
        printf("boundary: %zu bytes FAIL, %zu bytes OK\n", min_pool - 1,
               min_pool);
    }
    printf("OK\n");
    return 0;
}
