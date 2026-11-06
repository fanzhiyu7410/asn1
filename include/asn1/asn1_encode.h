/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 编码选项、输出缓冲与 writer 回调。契约见 docs/02-C-API规范.md 第 6、
 * 第 8、第 9 节与 docs/04-数据与内存模型.md 第 3 节。
 *
 * 本阶段基线只提供通用 DER 规范化编码；schema 感知编码（DEFAULT 省略）
 * 尚未落地，传入 schema 会被明确拒绝而不是静默按通用规则编码。
 */
#ifndef ASN1_ASN1_ENCODE_H_INCLUDED
#define ASN1_ASN1_ENCODE_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include <asn1/asn1_allocator.h>
#include <asn1/asn1_decode.h>
#include <asn1/asn1_error.h>
#include <asn1/asn1_export.h>
#include <asn1/asn1_schema.h>

typedef asn1_err_t (*asn1_write_fn)(void *user, const uint8_t *data,
                                    size_t size);

typedef struct asn1_writer {
    size_t struct_size;      /* 必须为 sizeof(asn1_writer_t) */
    void *user;
    asn1_write_fn write;     /* 全写或返回非零；库包装为 ASN1_E_IO_WRITE */
} asn1_writer_t;

typedef struct asn1_buf {
    uint8_t *data;
    size_t size;
    size_t capacity;
} asn1_buf_t;

/*
 * 编码选项。struct_size 必须为 sizeof(asn1_encode_options_t)；flags 基线
 * 必须为 0；schema 为 NULL 时按通用 DER 规范化规则编码。
 */
typedef struct asn1_encode_options {
    size_t struct_size;                 /* 必须为 sizeof(asn1_encode_options_t) */
    asn1_encoding_t encoding;           /* 基线只接受 DER */
    const asn1_schema_t *schema;        /* NULL 表示无 schema 编码 */
    uint32_t flags;                     /* ASN1_ENCODE_*，基线必须为 0 */
    uint32_t reserved[4];               /* 必须置零 */
} asn1_encode_options_t;

#ifdef __cplusplus
extern "C" {
#endif

/* 清零并写入 struct_size；默认 DER、无 schema、flags = 0。 */
ASN1_API void asn1_encode_options_init(asn1_encode_options_t *options);

/*
 * 编码到调用方 writer。writer 契约：返回 ASN1_OK 表示 size 个字节全部被
 * 接受；非零返回包装为 ASN1_E_IO_WRITE，原始值写入 callback_code。
 */
ASN1_API asn1_err_t asn1_encode_writer(asn1_ctx_t *ctx,
                                       const asn1_doc_t *doc,
                                       const asn1_encode_options_t *options,
                                       const asn1_writer_t *writer);

/*
 * 编码到上下文级分配的缓冲。成功时 out_buf 非空，调用方必须用
 * asn1_buf_release 归还，或由 asn1_ctx_destroy 兜底回收。
 * 失败时 out_buf 被清零。
 */
ASN1_API asn1_err_t asn1_encode_buffer(asn1_ctx_t *ctx,
                                       const asn1_doc_t *doc,
                                       const asn1_encode_options_t *options,
                                       asn1_buf_t *out_buf);

/*
 * 释放 asn1_encode_buffer 产出的缓冲并置零 data/size/capacity。
 * buf == NULL 或全零缓冲为空操作；跨上下文或非法缓冲返回
 * ASN1_E_INVALID_ARG 且不修改 buf。
 */
ASN1_API asn1_err_t asn1_buf_release(asn1_ctx_t *ctx, asn1_buf_t *buf);

#ifdef __cplusplus
}
#endif

#endif /* ASN1_ASN1_ENCODE_H_INCLUDED */
