/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 嵌入式最小用例：静态池、无堆、无标准 IO。
 *
 * 覆盖：
 *   1. 用 asn1_ctx_size_for_config 的返回值确认固定池够用；
 *   2. 用静态池创建上下文（配置里同时挂一个计数分配器，断言它从未被调用，
 *      以此证明该路径不触堆）；
 *   3. 解码一段 BER 并销毁文档；
 *   4. 手工构树（创建根/子节点、写值、封存）并销毁；
 *   5. 池恰好只够上下文时，asn1_doc_create 返回 ASN1_E_STATIC_POOL_EXHAUSTED。
 *
 * 不依赖 stdio/malloc，可直接链接到 freestanding 静态库后由
 * arm-none-eabi 交叉编译；宿主构建时同时注册为 CTest 用例。
 */

#include <stddef.h>
#include <stdint.h>

#include <asn1/asn1_allocator.h>
#include <asn1/asn1_build.h>
#include <asn1/asn1_decode.h>

/* 以联合体保证池起始地址满足库要求的最大对齐。 */
typedef union {
    long double ld;
    void *ptr;
    uint64_t u64;
} align_blob_t;

#define POOL_BYTES 16384u
static align_blob_t g_pool[POOL_BYTES / sizeof(align_blob_t)];

static int g_failures;
static int g_first_failure;

#define EMBED_CHECK(cond, id)         \
    do {                              \
        if (!(cond)) {                \
            ++g_failures;             \
            if (g_first_failure == 0) \
                g_first_failure = (id); /* 首次失败位置 */ \
        }                             \
    } while (0)

/* 计数分配器：静态池路径下必须保持 0 次调用。 */
static size_t g_alloc_calls;
static size_t g_free_calls;

static void *counting_alloc(void *user, size_t size)
{
    (void)user;
    (void)size;
    ++g_alloc_calls;
    return NULL;
}

static void counting_free(void *user, void *ptr)
{
    (void)user;
    (void)ptr;
    ++g_free_calls;
}

/* 一段规范 DER：SEQUENCE { INTEGER 5, INTEGER 0 }。 */
static const uint8_t k_ber[] = {0x30, 0x06, 0x02, 0x01, 0x05,
                                0x02, 0x01, 0x00};

static void check_decode_path(void)
{
    asn1_ctx_config_t config;
    asn1_allocator_t allocator;
    asn1_ctx_t *ctx = NULL;
    asn1_doc_t *doc = NULL;
    size_t required = 0;
    size_t consumed = 0;
    asn1_decode_options_t options;

    asn1_ctx_config_init(&config);

    allocator.struct_size = sizeof(allocator);
    allocator.user = NULL;
    allocator.alloc = counting_alloc;
    allocator.realloc = NULL;
    allocator.free = counting_free;

    EMBED_CHECK(asn1_ctx_size_for_config(&config, &required) == ASN1_OK, 1);
    EMBED_CHECK(required > 0, 2);
    EMBED_CHECK(required <= (size_t)sizeof(g_pool), 3);

    /* 静态池 + 计数分配器：池应承担全部内存。 */
    config.allocator = &allocator;
    config.static_pool = (void *)g_pool;
    config.static_pool_size = (size_t)sizeof(g_pool);

    EMBED_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_OK, 4);
    EMBED_CHECK(ctx != NULL, 5);

    asn1_decode_options_init(&options);
    EMBED_CHECK(asn1_decode_buffer(ctx, k_ber, sizeof(k_ber), &options, &doc,
                                   &consumed) == ASN1_OK, 6);
    EMBED_CHECK(doc != NULL, 7);
    EMBED_CHECK(consumed == sizeof(k_ber), 8);
    asn1_doc_destroy(doc);

    /* 手工构树：SEQUENCE { INTEGER 42 }。 */
    doc = NULL;
    EMBED_CHECK(asn1_doc_create(ctx, &doc) == ASN1_OK, 9);
    if (doc != NULL) {
        asn1_node_t *root = NULL;
        asn1_node_t *child = NULL;
        EMBED_CHECK(asn1_node_create(doc, NULL, ASN1_TAG_UNIVERSAL, 16, 1,
                                     &root) == ASN1_OK, 10);
        if (root != NULL) {
            EMBED_CHECK(asn1_node_create(doc, root, ASN1_TAG_UNIVERSAL, 2, 0,
                                         &child) == ASN1_OK, 11);
            if (child != NULL) {
                EMBED_CHECK(asn1_node_set_int64(child, 42) == ASN1_OK, 12);
            }
        }
        EMBED_CHECK(asn1_doc_seal(doc) == ASN1_OK, 13);
        asn1_doc_destroy(doc);
    }

    asn1_ctx_destroy(ctx);
    EMBED_CHECK(g_alloc_calls == 0, 14);
    EMBED_CHECK(g_free_calls == 0, 15);
}

static void check_pool_exhaustion(void)
{
    asn1_ctx_config_t config;
    asn1_ctx_t *ctx = NULL;
    asn1_doc_t *doc = NULL;
    size_t required = 0;

    asn1_ctx_config_init(&config);
    EMBED_CHECK(asn1_ctx_size_for_config(&config, &required) == ASN1_OK, 16);

    /* 池恰好容纳上下文本身：文档分配必须报耗尽，而不是回退到堆。 */
    config.static_pool = (void *)g_pool;
    config.static_pool_size = required;
    EMBED_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_OK, 17);
    if (ctx != NULL) {
        EMBED_CHECK(asn1_doc_create(ctx, &doc) ==
                        ASN1_E_STATIC_POOL_EXHAUSTED, 18);
        EMBED_CHECK(doc == NULL, 19);
        asn1_ctx_destroy(ctx);
    }

    /* 池比最小尺寸少 1 字节：上下文创建失败。 */
    asn1_ctx_config_init(&config);
    config.static_pool = (void *)g_pool;
    config.static_pool_size = (required > 0) ? required - 1 : 0;
    EMBED_CHECK(asn1_ctx_create(&config, &ctx) == ASN1_E_INVALID_CONFIG, 20);
}

int main(void)
{
    check_decode_path();
    check_pool_exhaustion();
    return (g_failures == 0) ? 0 : g_first_failure;
}
