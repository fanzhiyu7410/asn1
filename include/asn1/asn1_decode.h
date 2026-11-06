/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 解码选项、reader 与文档生命周期。契约见 docs/02-C-API规范.md 第 5.1、
 * 第 9 节与 docs/04-数据与内存模型.md 第 3 节。
 */
#ifndef ASN1_ASN1_DECODE_H_INCLUDED
#define ASN1_ASN1_DECODE_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include <asn1/asn1_allocator.h>
#include <asn1/asn1_error.h>
#include <asn1/asn1_export.h>

typedef struct asn1_doc  asn1_doc_t;
typedef struct asn1_node asn1_node_t;
typedef struct asn1_reader asn1_reader_t;

/* 解码/编码规则。基线解码接受 BER 与 DER；CER 与 NONE 不支持解码。 */
typedef enum asn1_encoding {
    ASN1_ENCODING_BER = 0,   /* 解码可接受；编码不单独提供 */
    ASN1_ENCODING_DER = 1,   /* 解码严格模式；编码目标 */
    ASN1_ENCODING_CER = 2,   /* 预留，基线不支持 */
    ASN1_ENCODING_NONE = 3   /* 无源编码：runtime 构树文档 */
} asn1_encoding_t;

/* ASN1_DECODE_* 位标志，语义见 docs/02-C-API规范.md 5.1。 */
#define ASN1_DECODE_COPY_INPUT ((uint32_t)(1u << 0))
#define ASN1_DECODE_STRICT_SCHEMA ((uint32_t)(1u << 1))
#define ASN1_DECODE_WARN_UNKNOWN_FIELD ((uint32_t)(1u << 2))
#define ASN1_DECODE_ALLOW_TRAILING ((uint32_t)(1u << 3))

/*
 * 解码选项。struct_size 必须为 sizeof(asn1_decode_options_t)。
 * options == NULL 等价于默认选项：借用输入、BER、未知字段静默保留、
 * 尾随数据拒绝、不启用 schema 严格校验。
 */
typedef struct asn1_decode_options {
    size_t struct_size;                 /* 必须为 sizeof(asn1_decode_options_t) */
    asn1_encoding_t encoding;           /* BER（默认）或 DER */
    uint32_t flags;                     /* ASN1_DECODE_* 位标志 */
    uint32_t max_depth;                 /* 0 表示用上下文默认；非 0 只能收紧 */
    uint32_t reserved[3];               /* 必须置零 */
} asn1_decode_options_t;

typedef asn1_err_t (*asn1_read_fn)(void *user, uint8_t *dst,
                                   size_t capacity, size_t *out_size);

struct asn1_reader {
    size_t struct_size;      /* 必须为 sizeof(asn1_reader_t) */
    void *user;
    asn1_read_fn read;       /* out_size == 0 表示输入结束 */
};

#ifdef __cplusplus
extern "C" {
#endif

/* 清零并写入 struct_size；默认 encoding = BER、flags = 0、max_depth = 0。 */
ASN1_API void asn1_decode_options_init(asn1_decode_options_t *options);

/*
 * 解码一块完整输入并构建文档树。默认借用输入（文档存续期间调用方必须
 * 保证输入有效且不变）；设置 ASN1_DECODE_COPY_INPUT 时复制进文档 arena。
 *
 * 成功时 *out_doc 非 NULL，consumed 写入从 data 消费的字节数。
 * 失败时 *out_doc 置 NULL，consumed 保持原值，并通过上下文错误状态
 * 提供 code/offset/depth/path。
 */
ASN1_API asn1_err_t asn1_decode_buffer(asn1_ctx_t *ctx,
                                       const uint8_t *data, size_t size,
                                       const asn1_decode_options_t *options,
                                       asn1_doc_t **out_doc,
                                       size_t *consumed);

/*
 * 从 reader 解码。reader 生命周期由调用方保证：实现会分段拉取直到 EOF，
 * 并把输入复制进文档，ASN1_DECODE_COPY_INPUT 按忽略处理。
 * 成功时 *out_doc 非 NULL，consumed 写入实际从 reader 拉取的字节数
 * （可能因预读大于顶层 TLV 长度）；失败时 consumed 保持原值。
 * IO 回调返回非零时对外返回 ASN1_E_IO_READ，原始回调码写入错误详情的
 * callback_code。
 */
ASN1_API asn1_err_t asn1_decode_reader(asn1_ctx_t *ctx,
                                       const asn1_reader_t *reader,
                                       const asn1_decode_options_t *options,
                                       asn1_doc_t **out_doc,
                                       size_t *consumed);

/* 销毁文档；doc == NULL 为空操作。销毁后所有节点指针立即失效。 */
ASN1_API void asn1_doc_destroy(asn1_doc_t *doc);

#ifdef __cplusplus
}
#endif

#endif /* ASN1_ASN1_DECODE_H_INCLUDED */
