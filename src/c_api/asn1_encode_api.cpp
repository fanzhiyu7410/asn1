/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 编码的 C ABI 边界：选项/句柄校验、输出缓冲所有权与 writer 适配。
 *
 * 职责：把公共编码接口转发到 der/asn1_encoder.h 或 schema/asn1_schema_encode.h，
 *       并在入口完成参数、状态与预算检查。options->schema 非空时使用 schema
 *       感知编码（DEFAULT 省略、字段顺序、SET/SET OF 排序、EXPLICIT ANY 重包）。
 * 依赖：core/asn1_context.h、types/asn1_dom.h、schema/asn1_schema.h、
 *       schema/asn1_schema_encode.h、der/asn1_encoder.h。
 */

#include <asn1/asn1.h>

#include "core/asn1_context.h"
#include "der/asn1_encoder.h"
#include "schema/asn1_schema.h"
#include "schema/asn1_schema_encode.h"
#include "types/asn1_dom.h"

namespace {

/* 输出缓冲头部：记录所有者上下文，供 asn1_buf_release 校验归属。 */
struct OutputHeader {
    uint32_t magic;
    uint32_t reserved;
    asn1::Context *owner;
};

constexpr uint32_t kOutputMagic = UINT32_C(0x4F555431); /* "OUT1" */

asn1::Context *validContext(asn1_ctx_t *handle) noexcept
{
    if (handle == nullptr) {
        return nullptr;
    }
    asn1::Context *ctx =
        static_cast<asn1::Context *>(static_cast<void *>(handle));
    if (ctx->m_magic != asn1::kContextMagic || ctx->m_dead) {
        return nullptr;
    }
    return ctx;
}

asn1::Document *validDocument(const asn1_doc_t *handle) noexcept
{
    if (handle == nullptr) {
        return nullptr;
    }
    asn1::Document *doc = static_cast<asn1::Document *>(
        const_cast<void *>(static_cast<const void *>(handle)));
    if (doc->magic != asn1::kDocumentMagic) {
        return nullptr;
    }
    return doc;
}

asn1::Schema *schemaOf(const asn1_schema_t *handle) noexcept
{
    if (handle == nullptr) {
        return nullptr;
    }
    return static_cast<asn1::Schema *>(
        const_cast<void *>(static_cast<const void *>(handle)));
}

asn1_err_t validateOptions(asn1::Context *ctx,
                           const asn1_encode_options_t *options,
                           asn1::Schema **outSchema) noexcept
{
    if (outSchema != nullptr) {
        *outSchema = nullptr;
    }
    if (options == nullptr) {
        return ASN1_OK;
    }

    if (options->struct_size != sizeof(asn1_encode_options_t)) {
        asn1::contextSetError(ctx, ASN1_E_INVALID_CONFIG, SIZE_MAX, 0);
        return ASN1_E_INVALID_CONFIG;
    }
    for (size_t i = 0; i < 4; ++i) {
        if (options->reserved[i] != 0) {
            asn1::contextSetError(ctx, ASN1_E_INVALID_CONFIG, SIZE_MAX, 0);
            return ASN1_E_INVALID_CONFIG;
        }
    }
    if (options->flags != 0) {
        asn1::contextSetError(ctx, ASN1_E_INVALID_CONFIG, SIZE_MAX, 0);
        return ASN1_E_INVALID_CONFIG;
    }
    if (options->encoding != ASN1_ENCODING_DER) {
        asn1::contextSetError(ctx, ASN1_E_UNSUPPORTED_ENCODING, SIZE_MAX, 0);
        return ASN1_E_UNSUPPORTED_ENCODING;
    }

    if (options->schema != nullptr) {
        asn1::Schema *schema = schemaOf(options->schema);
        if (schema->magic != asn1::kSchemaMagic) {
            asn1::contextSetError(ctx, ASN1_E_INVALID_ARG, SIZE_MAX, 0);
            return ASN1_E_INVALID_ARG;
        }
        if (!schema->sealed) {
            asn1::contextSetError(ctx, ASN1_E_INVALID_STATE, SIZE_MAX, 0);
            return ASN1_E_INVALID_STATE;
        }
        if (schema->rootTypeId == 0) {
            asn1::contextSetError(ctx, ASN1_E_INVALID_STATE, SIZE_MAX, 0);
            return ASN1_E_INVALID_STATE;
        }
        if (outSchema != nullptr) {
            *outSchema = schema;
        }
    }

    return ASN1_OK;
}

asn1_err_t measureWithinBudget(asn1::Context *ctx, const asn1::Document *doc,
                               const asn1::Schema *schema, size_t *outSize) noexcept
{
    size_t size = 0;
    const asn1_err_t rc =
        schema != nullptr
            ? asn1::schemaMeasureDocument(ctx, doc, schema, &size)
            : asn1::derMeasureDocument(ctx, doc, &size);
    if (rc != ASN1_OK) {
        return rc;
    }
    if (static_cast<uint64_t>(size) > ctx->m_maxOutputBytes) {
        asn1::contextSetError(ctx, ASN1_E_OUTPUT_LIMIT, SIZE_MAX, 0);
        return ASN1_E_OUTPUT_LIMIT;
    }
    *outSize = size;
    return ASN1_OK;
}

asn1_err_t encodeDocument(asn1::Context *ctx, const asn1::Document *doc,
                          const asn1::Schema *schema, uint8_t *dst,
                          size_t capacity) noexcept
{
    if (schema != nullptr) {
        return asn1::schemaEncodeDocument(ctx, doc, schema, dst, capacity);
    }
    return asn1::derEncodeDocument(ctx, doc, dst, capacity);
}

} /* namespace */

extern "C" void asn1_encode_options_init(asn1_encode_options_t *options)
{
    if (options == nullptr) {
        return;
    }
    for (size_t i = 0; i < sizeof(*options); ++i) {
        reinterpret_cast<uint8_t *>(options)[i] = 0;
    }
    options->struct_size = sizeof(asn1_encode_options_t);
    options->encoding = ASN1_ENCODING_DER;
}

extern "C" asn1_err_t asn1_encode_writer(asn1_ctx_t *ctxHandle,
                                         const asn1_doc_t *docHandle,
                                         const asn1_encode_options_t *options,
                                         const asn1_writer_t *writer)
{
    asn1::Context *ctx = validContext(ctxHandle);
    if (ctx == nullptr) {
        return ASN1_E_INVALID_ARG;
    }

    asn1::Document *doc = validDocument(const_cast<asn1_doc_t *>(docHandle));
    if (doc == nullptr || doc->ctx != ctx) {
        asn1::contextSetError(ctx, ASN1_E_INVALID_ARG, SIZE_MAX, 0);
        return ASN1_E_INVALID_ARG;
    }
    if (!doc->sealed || doc->root == nullptr) {
        asn1::contextSetError(ctx, ASN1_E_INVALID_STATE, SIZE_MAX, 0);
        return ASN1_E_INVALID_STATE;
    }
    if (writer == nullptr || writer->write == nullptr) {
        asn1::contextSetError(ctx, ASN1_E_INVALID_ARG, SIZE_MAX, 0);
        return ASN1_E_INVALID_ARG;
    }
    if (writer->struct_size != sizeof(asn1_writer_t)) {
        asn1::contextSetError(ctx, ASN1_E_INVALID_CONFIG, SIZE_MAX, 0);
        return ASN1_E_INVALID_CONFIG;
    }

    asn1::Schema *schema = nullptr;
    const asn1_err_t optionRc = validateOptions(ctx, options, &schema);
    if (optionRc != ASN1_OK) {
        return optionRc;
    }

    size_t size = 0;
    const asn1_err_t measureRc = measureWithinBudget(ctx, doc, schema, &size);
    if (measureRc != ASN1_OK) {
        return measureRc;
    }

    void *raw = nullptr;
    const asn1_err_t allocRc = asn1::contextAllocate(
        ctx, size == 0 ? 1 : size, asn1::AllocationKind::kGeneric, &raw);
    if (allocRc != ASN1_OK) {
        return allocRc;
    }

    const asn1_err_t encodeRc =
        encodeDocument(ctx, doc, schema, static_cast<uint8_t *>(raw), size);
    if (encodeRc != ASN1_OK) {
        asn1::contextRelease(ctx, raw);
        return encodeRc;
    }

    const asn1_err_t writeRc =
        writer->write(writer->user, static_cast<const uint8_t *>(raw), size);
    asn1::contextRelease(ctx, raw);
    if (writeRc != ASN1_OK) {
        /* 单次回调失败：按契约未确认接收任何字节，offset 记 0。 */
        asn1::contextSetError(ctx, ASN1_E_IO_WRITE, 0, 0);
        ctx->m_callbackCode = writeRc;
        return ASN1_E_IO_WRITE;
    }
    return ASN1_OK;
}

extern "C" asn1_err_t asn1_encode_buffer(asn1_ctx_t *ctxHandle,
                                         const asn1_doc_t *docHandle,
                                         const asn1_encode_options_t *options,
                                         asn1_buf_t *out_buf)
{
    if (out_buf == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    out_buf->data = nullptr;
    out_buf->size = 0;
    out_buf->capacity = 0;

    asn1::Context *ctx = validContext(ctxHandle);
    if (ctx == nullptr) {
        return ASN1_E_INVALID_ARG;
    }

    asn1::Document *doc = validDocument(const_cast<asn1_doc_t *>(docHandle));
    if (doc == nullptr || doc->ctx != ctx) {
        asn1::contextSetError(ctx, ASN1_E_INVALID_ARG, SIZE_MAX, 0);
        return ASN1_E_INVALID_ARG;
    }
    if (!doc->sealed || doc->root == nullptr) {
        asn1::contextSetError(ctx, ASN1_E_INVALID_STATE, SIZE_MAX, 0);
        return ASN1_E_INVALID_STATE;
    }

    asn1::Schema *schema = nullptr;
    const asn1_err_t optionRc = validateOptions(ctx, options, &schema);
    if (optionRc != ASN1_OK) {
        return optionRc;
    }

    size_t size = 0;
    const asn1_err_t measureRc = measureWithinBudget(ctx, doc, schema, &size);
    if (measureRc != ASN1_OK) {
        return measureRc;
    }
    if (size > SIZE_MAX - sizeof(OutputHeader)) {
        asn1::contextSetError(ctx, ASN1_E_OUTPUT_LIMIT, SIZE_MAX, 0);
        return ASN1_E_OUTPUT_LIMIT;
    }

    void *raw = nullptr;
    const asn1_err_t allocRc = asn1::contextAllocate(
        ctx, sizeof(OutputHeader) + size, asn1::AllocationKind::kOutputBuffer,
        &raw);
    if (allocRc != ASN1_OK) {
        return allocRc;
    }

    OutputHeader *header = static_cast<OutputHeader *>(raw);
    header->magic = kOutputMagic;
    header->reserved = 0;
    header->owner = ctx;
    uint8_t *payload = reinterpret_cast<uint8_t *>(header + 1);

    const asn1_err_t encodeRc = encodeDocument(ctx, doc, schema, payload, size);
    if (encodeRc != ASN1_OK) {
        asn1::contextRelease(ctx, raw);
        return encodeRc;
    }

    out_buf->data = payload;
    out_buf->size = size;
    out_buf->capacity = size;
    return ASN1_OK;
}

extern "C" asn1_err_t asn1_buf_release(asn1_ctx_t *ctxHandle, asn1_buf_t *buf)
{
    if (buf == nullptr) {
        return ASN1_OK;
    }
    if (buf->data == nullptr && buf->size == 0 && buf->capacity == 0) {
        return ASN1_OK;
    }

    asn1::Context *ctx = validContext(ctxHandle);
    if (ctx == nullptr || buf->data == nullptr) {
        return ASN1_E_INVALID_ARG;
    }

    OutputHeader *header = reinterpret_cast<OutputHeader *>(buf->data) - 1;
    if (header->magic != kOutputMagic || header->owner != ctx) {
        return ASN1_E_INVALID_ARG;
    }

    asn1::contextRelease(ctx, header);
    buf->data = nullptr;
    buf->size = 0;
    buf->capacity = 0;
    return ASN1_OK;
}
