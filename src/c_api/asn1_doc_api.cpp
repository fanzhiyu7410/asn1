/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * runtime 构树 C API：文档创建/封存、节点创建与内容设置。
 *
 * 职责：校验公共参数并调用 types/asn1_dom.h 的构树操作。
 * 依赖：types/asn1_dom.h、core/asn1_context.h。
 */

// ============================================================================
// 依赖与前置声明
// ============================================================================

#include <asn1/asn1.h>

#include "core/asn1_context.h"
#include "types/asn1_dom.h"

#include <cstring>

namespace {

asn1::Document *documentOf(asn1_doc_t *handle) noexcept
{
    return static_cast<asn1::Document *>(static_cast<void *>(handle));
}

asn1::Node *nodeOf(asn1_node_t *handle) noexcept
{
    return static_cast<asn1::Node *>(static_cast<void *>(handle));
}

/* 返回子标识符的 base-128 编码字节数。 */
size_t subidentifierOctets(uint64_t value) noexcept
{
    size_t count = 1;
    while (value >= 128) {
        value >>= 7;
        ++count;
    }
    return count;
}

void encodeSubidentifier(uint64_t value, uint8_t *out,
                         size_t *outCursor) noexcept
{
    uint8_t parts[10];
    size_t count = 0;
    do {
        parts[count++] = static_cast<uint8_t>(value & 0x7Fu);
        value >>= 7;
    } while (value != 0);

    size_t cursor = *outCursor;
    for (size_t i = count; i > 0; --i) {
        uint8_t byte = parts[i - 1];
        if (i > 1) {
            byte |= 0x80u;
        }
        out[cursor++] = byte;
    }
    *outCursor = cursor;
}

/* 解析十进制无符号数；失败返回 false。 */
bool parseDecimal(const char *text, size_t *cursor, uint64_t *outValue) noexcept
{
    size_t pos = *cursor;
    if (text[pos] < '0' || text[pos] > '9') {
        return false;
    }
    uint64_t value = 0;
    while (text[pos] >= '0' && text[pos] <= '9') {
        const uint64_t digit = static_cast<uint64_t>(text[pos] - '0');
        if (value > (UINT64_MAX - digit) / 10) {
            return false;
        }
        value = value * 10 + digit;
        ++pos;
    }
    *cursor = pos;
    *outValue = value;
    return true;
}

} /* namespace */

// ============================================================================
// 类型定义
// ============================================================================

// 内部类型位于 types/asn1_dom.h。

// ============================================================================
// 静态常量 / 内部辅助类型
// ============================================================================

// 无文件级常量。

// ============================================================================
// 构造与析构
// ============================================================================

extern "C" asn1_err_t asn1_doc_create(asn1_ctx_t *ctxHandle,
                                       asn1_doc_t **out_doc)
{
    if (ctxHandle == nullptr || out_doc == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    *out_doc = nullptr;

    asn1::Context *ctx =
        static_cast<asn1::Context *>(static_cast<void *>(ctxHandle));
    if (ctx->m_magic != asn1::kContextMagic || ctx->m_dead) {
        return ASN1_E_INVALID_ARG;
    }

    asn1::Document *doc = nullptr;
    const asn1_err_t rc = asn1::documentCreate(ctx, &doc);
    if (rc != ASN1_OK) {
        return rc;
    }

    *out_doc = reinterpret_cast<asn1_doc_t *>(doc);
    return ASN1_OK;
}

extern "C" asn1_err_t asn1_doc_seal(asn1_doc_t *handle)
{
    if (handle == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    asn1::Document *doc = documentOf(handle);
    if (doc->magic != asn1::kDocumentMagic) {
        return ASN1_E_INVALID_ARG;
    }
    return asn1::documentSeal(doc);
}

extern "C" asn1_err_t asn1_node_create(asn1_doc_t *docHandle,
                                       asn1_node_t *parentHandle,
                                       asn1_tag_class_t tag_class,
                                       uint32_t tag_number, int constructed,
                                       asn1_node_t **out_node)
{
    if (docHandle == nullptr || out_node == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    *out_node = nullptr;

    asn1::Document *doc = documentOf(docHandle);
    if (doc->magic != asn1::kDocumentMagic) {
        return ASN1_E_INVALID_ARG;
    }

    if (tag_class < ASN1_TAG_UNIVERSAL || tag_class > ASN1_TAG_PRIVATE) {
        return ASN1_E_INVALID_ARG;
    }
    if (tag_class == ASN1_TAG_UNIVERSAL && tag_number == 0) {
        /* UNIVERSAL 0 是 EOC，不是合法内容类型。 */
        asn1::contextSetError(doc->ctx, ASN1_E_INVALID_ARG, SIZE_MAX, 0);
        return ASN1_E_INVALID_ARG;
    }

    asn1::Node *parent = nullptr;
    uint32_t depth = 0;
    if (parentHandle != nullptr) {
        parent = nodeOf(parentHandle);
        if (parent->document != doc) {
            asn1::contextSetError(doc->ctx, ASN1_E_INVALID_ARG, SIZE_MAX, 0);
            return ASN1_E_INVALID_ARG;
        }
        depth = parent->depth + 1;
    }

    asn1::Node *node = nullptr;
    const asn1_err_t rc = asn1::documentCreateNode(
        doc, parent, static_cast<uint32_t>(tag_class), tag_number,
        constructed != 0, depth, SIZE_MAX, 0, nullptr, 0, &node);
    if (rc != ASN1_OK) {
        return rc;
    }

    *out_node = reinterpret_cast<asn1_node_t *>(node);
    return ASN1_OK;
}

// ============================================================================
// 内容设置
// ============================================================================

extern "C" asn1_err_t asn1_node_set_content(asn1_node_t *nodeHandle,
                                            const uint8_t *data, size_t size)
{
    if (nodeHandle == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    asn1::Node *node = nodeOf(nodeHandle);
    if (node->document == nullptr ||
        node->document->magic != asn1::kDocumentMagic) {
        return ASN1_E_INVALID_ARG;
    }
    return asn1::documentSetNodeContent(node->document, node, data, size);
}

extern "C" asn1_err_t asn1_node_set_bool(asn1_node_t *nodeHandle, int value)
{
    if (nodeHandle == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const uint8_t content = value != 0 ? 0xFFu : 0x00u;
    return asn1_node_set_content(nodeHandle, &content, 1);
}

extern "C" asn1_err_t asn1_node_set_int64(asn1_node_t *nodeHandle,
                                          int64_t value)
{
    if (nodeHandle == nullptr) {
        return ASN1_E_INVALID_ARG;
    }

    uint8_t bytes[8];
    const uint64_t raw = static_cast<uint64_t>(value);
    for (size_t i = 0; i < 8; ++i) {
        bytes[7 - i] = static_cast<uint8_t>((raw >> (8 * i)) & 0xFFu);
    }

    size_t first = 0;
    if (value >= 0) {
        while (first < 7 && bytes[first] == 0x00u &&
               bytes[first + 1] < 0x80u) {
            ++first;
        }
    } else {
        while (first < 7 && bytes[first] == 0xFFu &&
               (bytes[first + 1] & 0x80u) != 0) {
            ++first;
        }
    }

    const size_t size = 8 - first;
    return asn1_node_set_content(nodeHandle, bytes + first, size);
}

extern "C" asn1_err_t asn1_node_set_oid(asn1_node_t *nodeHandle,
                                        const char *dotted)
{
    if (nodeHandle == nullptr || dotted == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    asn1::Node *node = nodeOf(nodeHandle);
    if (node->document == nullptr ||
        node->document->magic != asn1::kDocumentMagic) {
        return ASN1_E_INVALID_ARG;
    }

    /* 第一遍：校验点分文本并计算编码长度。 */
    size_t cursor = 0;
    uint64_t firstArc = 0;
    uint64_t secondArc = 0;
    if (!parseDecimal(dotted, &cursor, &firstArc) || dotted[cursor] != '.') {
        return ASN1_E_INVALID_VALUE;
    }
    ++cursor;
    if (!parseDecimal(dotted, &cursor, &secondArc) || firstArc > 2) {
        return ASN1_E_INVALID_VALUE;
    }
    if (firstArc < 2 && secondArc > 39) {
        return ASN1_E_INVALID_VALUE;
    }

    if (secondArc > UINT64_MAX - firstArc * 40u) {
        return ASN1_E_INVALID_VALUE;
    }
    uint64_t combined = firstArc * 40u + secondArc;

    size_t total = subidentifierOctets(combined);
    while (dotted[cursor] == '.') {
        ++cursor;
        uint64_t arc = 0;
        if (!parseDecimal(dotted, &cursor, &arc)) {
            return ASN1_E_INVALID_VALUE;
        }
        const size_t octets = subidentifierOctets(arc);
        if (total > SIZE_MAX - octets) {
            return ASN1_E_INVALID_VALUE;
        }
        total += octets;
    }
    if (dotted[cursor] != '\0') {
        return ASN1_E_INVALID_VALUE;
    }

    /* 第二遍：写入文档 arena。 */
    void *buffer = nullptr;
    const asn1_err_t rc =
        asn1::documentAllocate(node->document, total, &buffer);
    if (rc != ASN1_OK) {
        return rc;
    }

    uint8_t *encoded = static_cast<uint8_t *>(buffer);
    size_t outCursor = 0;
    encodeSubidentifier(combined, encoded, &outCursor);

    cursor = 0;
    (void)parseDecimal(dotted, &cursor, &firstArc);
    ++cursor;
    (void)parseDecimal(dotted, &cursor, &secondArc);
    while (dotted[cursor] == '.') {
        ++cursor;
        uint64_t arc = 0;
        (void)parseDecimal(dotted, &cursor, &arc);
        encodeSubidentifier(arc, encoded, &outCursor);
    }

    return asn1::documentAttachNodeContent(node->document, node, encoded,
                                           total);
}

extern "C" asn1_err_t asn1_node_set_utf8(asn1_node_t *nodeHandle,
                                         const char *text, size_t size)
{
    if (nodeHandle == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    if (text == nullptr && size != 0) {
        return ASN1_E_INVALID_ARG;
    }
    return asn1_node_set_content(nodeHandle,
                                 reinterpret_cast<const uint8_t *>(text),
                                 size);
}
