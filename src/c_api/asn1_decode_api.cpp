/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 解码 C API 边界：选项校验、文档生命周期与 BER 解码入口。
 *
 * 职责：把公共选项转换为内部参数并调用 ber 解码器。
 * 依赖：ber/asn1_ber_decoder.h、types/asn1_dom.h。
 */

// ============================================================================
// 依赖与前置声明
// ============================================================================

#include <asn1/asn1.h>

#include "ber/asn1_ber_decoder.h"
#include "core/asn1_context.h"
#include "types/asn1_dom.h"

namespace {

asn1::Context *contextOf(asn1_ctx_t *handle) noexcept
{
    return static_cast<asn1::Context *>(static_cast<void *>(handle));
}

asn1::Document *documentOf(asn1_doc_t *handle) noexcept
{
    return static_cast<asn1::Document *>(static_cast<void *>(handle));
}

/* 已知的 ASN1_DECODE_* 位；其余位视为配置错误。 */
constexpr uint32_t kKnownDecodeFlags =
    ASN1_DECODE_COPY_INPUT | ASN1_DECODE_STRICT_SCHEMA |
    ASN1_DECODE_WARN_UNKNOWN_FIELD | ASN1_DECODE_ALLOW_TRAILING;

asn1_err_t validateDecodeOptions(const asn1::Context *ctx,
                                 const asn1_decode_options_t *options,
                                 uint32_t *outMaxDepth, bool *outCopyInput,
                                 bool *outAllowTrailing) noexcept
{
    uint32_t maxDepth = ctx->m_maxDepth;
    bool copyInput = false;
    bool allowTrailing = false;

    if (options != nullptr) {
        if (options->struct_size != sizeof(asn1_decode_options_t)) {
            return ASN1_E_INVALID_CONFIG;
        }
        if (options->reserved[0] != 0 || options->reserved[1] != 0 ||
            options->reserved[2] != 0) {
            return ASN1_E_INVALID_CONFIG;
        }
        if (options->encoding != ASN1_ENCODING_BER &&
            options->encoding != ASN1_ENCODING_DER) {
            return ASN1_E_UNSUPPORTED_ENCODING;
        }
        if ((options->flags & ~kKnownDecodeFlags) != 0) {
            return ASN1_E_INVALID_CONFIG;
        }
        if ((options->flags & ASN1_DECODE_STRICT_SCHEMA) != 0) {
            /* 本调用没有 schema 参数，严格 schema 模式无法启用。 */
            return ASN1_E_INVALID_ARG;
        }
        if (options->max_depth != 0) {
            if (options->max_depth > ctx->m_maxDepth) {
                return ASN1_E_INVALID_CONFIG;
            }
            maxDepth = options->max_depth;
        }
        copyInput = (options->flags & ASN1_DECODE_COPY_INPUT) != 0;
        allowTrailing = (options->flags & ASN1_DECODE_ALLOW_TRAILING) != 0;
    }

    *outMaxDepth = maxDepth;
    *outCopyInput = copyInput;
    *outAllowTrailing = allowTrailing;
    return ASN1_OK;
}

} /* namespace */

// ============================================================================
// 类型定义
// ============================================================================

// 内部类型位于 core/context 与 types/dom 头文件。

// ============================================================================
// 静态常量 / 内部辅助类型
// ============================================================================

// kKnownDecodeFlags 定义于上方匿名命名空间。

// ============================================================================
// 构造与析构
// ============================================================================

extern "C" void asn1_decode_options_init(asn1_decode_options_t *options)
{
    if (options == nullptr) {
        return;
    }
    options->struct_size = sizeof(asn1_decode_options_t);
    options->encoding = ASN1_ENCODING_BER;
    options->flags = 0;
    options->max_depth = 0;
    options->reserved[0] = 0;
    options->reserved[1] = 0;
    options->reserved[2] = 0;
}

extern "C" asn1_err_t asn1_decode_buffer(asn1_ctx_t *ctxHandle,
                                         const uint8_t *data, size_t size,
                                         const asn1_decode_options_t *options,
                                         asn1_doc_t **out_doc,
                                         size_t *consumed)
{
    if (out_doc == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    *out_doc = nullptr;
    if (ctxHandle == nullptr) {
        return ASN1_E_INVALID_ARG;
    }

    asn1::Context *ctx = contextOf(ctxHandle);
    if (ctx->m_magic != asn1::kContextMagic || ctx->m_dead) {
        return ASN1_E_INVALID_ARG;
    }

    if (data == nullptr && size != 0) {
        asn1::contextSetError(ctx, ASN1_E_INVALID_ARG, SIZE_MAX, 0);
        return ASN1_E_INVALID_ARG;
    }

    uint32_t maxDepth = 0;
    bool copyInput = false;
    bool allowTrailing = false;
    const asn1_err_t rc = validateDecodeOptions(ctx, options, &maxDepth,
                                                &copyInput, &allowTrailing);
    if (rc != ASN1_OK) {
        asn1::contextSetError(ctx, rc, SIZE_MAX, 0);
        return rc;
    }

    const asn1_encoding_t encoding =
        options == nullptr ? ASN1_ENCODING_BER : options->encoding;

    /* 文档约定：下一次解码开始时清空上一轮告警。 */
    asn1::contextClearWarnings(ctx);

    asn1::Document *doc = nullptr;
    const asn1_err_t decodeRc =
        asn1::decodeBuffer(ctx, data, size, maxDepth, copyInput, allowTrailing,
                           encoding, &doc, consumed);
    if (decodeRc != ASN1_OK) {
        return decodeRc;
    }

    *out_doc = reinterpret_cast<asn1_doc_t *>(doc);
    return ASN1_OK;
}

extern "C" asn1_err_t asn1_decode_reader(asn1_ctx_t *ctxHandle,
                                         const asn1_reader_t *reader,
                                         const asn1_decode_options_t *options,
                                         asn1_doc_t **out_doc,
                                         size_t *consumed)
{
    if (out_doc == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    *out_doc = nullptr;
    if (ctxHandle == nullptr || reader == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    asn1::Context *ctx = contextOf(ctxHandle);
    if (ctx->m_magic != asn1::kContextMagic || ctx->m_dead) {
        return ASN1_E_INVALID_ARG;
    }
    uint32_t maxDepth = 0;
    bool copyInput = false;
    bool allowTrailing = false;
    const asn1_err_t optionRc = validateDecodeOptions(ctx, options, &maxDepth,
                                                     &copyInput, &allowTrailing);
    if (optionRc != ASN1_OK) {
        asn1::contextSetError(ctx, optionRc, SIZE_MAX, 0);
        return optionRc;
    }
    /* reader 生命周期由调用方保证：输入总是复制进文档，COPY_INPUT 忽略。 */
    (void)copyInput;

    const asn1_encoding_t encoding =
        options == nullptr ? ASN1_ENCODING_BER : options->encoding;

    asn1::contextClearWarnings(ctx);

    uint8_t *buffer = nullptr;
    size_t used = 0;
    asn1_err_t rc = asn1::readReaderInput(ctx, reader, &buffer, &used);
    if (rc != ASN1_OK) {
        return rc;
    }

    asn1::Document *doc = nullptr;
    size_t rootEnd = 0;
    rc = asn1::decodeBuffer(ctx, buffer, used, maxDepth, true, allowTrailing,
                            encoding, &doc, &rootEnd);
    asn1::contextRelease(ctx, buffer);
    if (rc != ASN1_OK) {
        return rc;
    }
    /* consumed 为实际拉取字节数：允许因预读大于顶层 TLV 长度。 */
    if (consumed != nullptr) {
        *consumed = used;
    }
    *out_doc = reinterpret_cast<asn1_doc_t *>(doc);
    return ASN1_OK;
}

extern "C" void asn1_doc_destroy(asn1_doc_t *handle)
{
    if (handle == nullptr) {
        return;
    }
    asn1::Document *doc = documentOf(handle);
    if (doc->magic != asn1::kDocumentMagic) {
        return;
    }
    asn1::documentDestroy(doc);
}
