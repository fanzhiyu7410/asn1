/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 语义读取：BOOLEAN、INTEGER/ENUMERATED、OCTET STRING、BIT STRING、OID
 * 与字符串原始字节。
 *
 * 职责：按 docs/02 6.6 与 docs/03 的取值规则解析内容。
 * 依赖：types/asn1_dom.h、types/asn1_value.h。
 */

// ============================================================================
// 依赖与前置声明
// ============================================================================

#include <asn1/asn1.h>

#include "types/asn1_dom.h"
#include "types/asn1_value.h"

#include <cstring>

namespace {

asn1::Node *nodeOf(const asn1_node_t *handle) noexcept
{
    return const_cast<asn1::Node *>(
        static_cast<const asn1::Node *>(static_cast<const void *>(handle)));
}

/* 变长 base-128 子标识符解码；overflow 返回 false。 */
bool decodeSubidentifier(const uint8_t *content, size_t size, size_t *cursor,
                         uint64_t *outValue) noexcept
{
    size_t pos = *cursor;
    uint64_t value = 0;
    while (pos < size) {
        const uint8_t byte = content[pos++];
        if (value > (UINT64_MAX - static_cast<uint64_t>(byte & 0x7Fu)) / 128u) {
            return false;
        }
        value = value * 128u + static_cast<uint64_t>(byte & 0x7Fu);
        if ((byte & 0x80u) == 0) {
            *cursor = pos;
            *outValue = value;
            return true;
        }
    }
    return false;
}

/* 十进制无符号追加；返回写入字节数。 */
size_t appendDecimal(char *dst, uint64_t value) noexcept
{
    char digits[20];
    size_t count = 0;
    do {
        digits[count++] = static_cast<char>('0' + (value % 10u));
        value /= 10u;
    } while (value != 0);

    size_t written = 0;
    for (size_t i = count; i > 0; --i) {
        dst[written++] = digits[i - 1];
    }
    return written;
}

/* 构造 BIT STRING 合并统计；按位累加，支持各段带不同 unused_bits。 */
struct BitMerge {
    size_t payloadBytes; /* 各段 payload 字节总数，用于分配上界 */
    size_t totalBits;    /* 有效位总数 */
    bool any;
};

asn1_err_t collectBitLeaves(const asn1::Node *node, BitMerge *merge) noexcept
{
    if (asn1::nodeIsConstructed(node)) {
        const asn1::Node *child = node->firstChild;
        while (child != nullptr) {
            asn1_err_t rc = collectBitLeaves(child, merge);
            if (rc != ASN1_OK) {
                return rc;
            }
            child = child->nextSibling;
        }
        return ASN1_OK;
    }

    if (asn1::universalTagNumber(node) != 3u) {
        return ASN1_E_MALFORMED_VALUE;
    }
    if (node->contentSize == 0 || node->content == nullptr) {
        return ASN1_E_MALFORMED_VALUE;
    }
    const uint8_t unused = node->content[0];
    if (unused > 7u) {
        return ASN1_E_MALFORMED_VALUE;
    }
    const size_t payload = node->contentSize - 1;
    if (payload == 0 && unused != 0) {
        return ASN1_E_MALFORMED_VALUE;
    }
    if (payload > (SIZE_MAX - static_cast<size_t>(unused)) / 8u) {
        return ASN1_E_MEMORY_LIMIT;
    }
    const size_t validBits = payload * 8u - static_cast<size_t>(unused);
    if (merge->payloadBytes > SIZE_MAX - payload ||
        merge->totalBits > SIZE_MAX - validBits) {
        return ASN1_E_MEMORY_LIMIT;
    }
    merge->payloadBytes += payload;
    merge->totalBits += validBits;
    merge->any = true;
    return ASN1_OK;
}

/* 按位拼接各段；*bitCursor 为已写入的有效位数。 */
asn1_err_t copyBitLeaves(const asn1::Node *node, uint8_t *dst,
                         size_t *bitCursor) noexcept
{
    if (asn1::nodeIsConstructed(node)) {
        const asn1::Node *child = node->firstChild;
        while (child != nullptr) {
            asn1_err_t rc = copyBitLeaves(child, dst, bitCursor);
            if (rc != ASN1_OK) {
                return rc;
            }
            child = child->nextSibling;
        }
        return ASN1_OK;
    }

    if (node->contentSize <= 1 || node->content == nullptr) {
        return ASN1_OK;
    }
    const uint8_t unused = node->content[0];
    const size_t validBits =
        (node->contentSize - 1) * 8u - static_cast<size_t>(unused);
    const uint8_t *src = node->content + 1;
    for (size_t i = 0; i < validBits; ++i) {
        if ((src[i >> 3] & static_cast<uint8_t>(0x80u >> (i & 7u))) != 0) {
            const size_t target = *bitCursor + i;
            dst[target >> 3] |=
                static_cast<uint8_t>(0x80u >> (target & 7u));
        }
    }
    *bitCursor += validBits;
    return ASN1_OK;
}

} /* namespace */

// ============================================================================
// 类型定义
// ============================================================================

// BitMerge 定义于上方匿名命名空间。

// ============================================================================
// 静态常量 / 内部辅助类型
// ============================================================================

// 无文件级常量。

// ============================================================================
// 构造与析构
// ============================================================================

// 无独立生命周期。

// ============================================================================
// 公共接口
// ============================================================================

extern "C" asn1_err_t asn1_node_get_bool(const asn1_node_t *handle,
                                         int *out_value)
{
    if (handle == nullptr || out_value == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1::Node *node = nodeOf(handle);
    if (asn1::universalTagNumber(node) != 1u ||
        asn1::nodeIsConstructed(node) || node->contentSize != 1 ||
        node->content == nullptr) {
        return ASN1_E_MALFORMED_VALUE;
    }

    const uint8_t value = node->content[0];
    if (value == 0x00u) {
        *out_value = 0;
        return ASN1_OK;
    }
    if (node->document->encoding == ASN1_ENCODING_DER && value != 0xFFu) {
        return ASN1_E_NON_CANONICAL;
    }
    *out_value = 1;
    return ASN1_OK;
}

extern "C" asn1_err_t asn1_node_get_int64(const asn1_node_t *handle,
                                          int64_t *out_value)
{
    if (handle == nullptr || out_value == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1::Node *node = nodeOf(handle);
    const uint32_t tag = asn1::universalTagNumber(node);
    if (tag != 2u && tag != 10u) {
        return ASN1_E_INVALID_VALUE;
    }
    if (asn1::nodeIsConstructed(node) || node->contentSize == 0 ||
        node->content == nullptr) {
        return ASN1_E_MALFORMED_VALUE;
    }

    const uint8_t *content = node->content;
    size_t size = node->contentSize;

    if (size > 8) {
        const bool negative = (content[0] & 0x80u) != 0;
        const uint8_t extension = negative ? 0xFFu : 0x00u;
        for (size_t i = 0; i + 8 < size; ++i) {
            if (content[i] != extension) {
                return ASN1_E_RANGE;
            }
        }
        const uint8_t firstKept = content[size - 8];
        if (((firstKept & 0x80u) != 0) != negative) {
            return ASN1_E_RANGE;
        }
        content += size - 8;
        size = 8;
    }

    uint64_t raw = 0;
    if ((content[0] & 0x80u) != 0) {
        raw = UINT64_MAX;
    }
    for (size_t i = 0; i < size; ++i) {
        raw = (raw << 8) | static_cast<uint64_t>(content[i]);
    }

    *out_value = static_cast<int64_t>(raw);
    return ASN1_OK;
}

extern "C" asn1_err_t asn1_node_get_octets(const asn1_node_t *handle,
                                           const uint8_t **out_data,
                                           size_t *out_size)
{
    if (handle == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1::Node *node = nodeOf(handle);
    if (asn1::universalTagNumber(node) != 4u) {
        return ASN1_E_INVALID_VALUE;
    }
    return mergePrimitiveContent(node, out_data, out_size);
}

extern "C" asn1_err_t asn1_node_get_raw_string(const asn1_node_t *handle,
                                               const uint8_t **out_data,
                                               size_t *out_size)
{
    if (handle == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1::Node *node = nodeOf(handle);
    return mergePrimitiveContent(node, out_data, out_size);
}

extern "C" asn1_err_t asn1_node_get_bits(const asn1_node_t *handle,
                                         const uint8_t **out_data,
                                         size_t *out_size,
                                         size_t *out_bit_length,
                                         uint8_t *out_unused_bits)
{
    if (handle == nullptr || out_data == nullptr || out_size == nullptr ||
        out_bit_length == nullptr || out_unused_bits == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1::Node *node = nodeOf(handle);
    if (asn1::universalTagNumber(node) != 3u) {
        return ASN1_E_INVALID_VALUE;
    }
    if (asn1::nodeIsConstructed(node) &&
        node->document->encoding == ASN1_ENCODING_DER) {
        return ASN1_E_NON_CANONICAL;
    }

    if (!asn1::nodeIsConstructed(node)) {
        if (node->contentSize == 0 || node->content == nullptr) {
            return ASN1_E_MALFORMED_VALUE;
        }
        const uint8_t unused = node->content[0];
        if (unused > 7u) {
            return ASN1_E_MALFORMED_VALUE;
        }
        const size_t payload = node->contentSize - 1;
        if (payload == 0 && unused != 0) {
            return ASN1_E_MALFORMED_VALUE;
        }
        if (payload > SIZE_MAX / 8u) {
            return ASN1_E_MEMORY_LIMIT;
        }
        *out_data = payload == 0 ? nullptr : node->content + 1;
        *out_size = payload;
        *out_unused_bits = unused;
        *out_bit_length = payload * 8u - static_cast<size_t>(unused);
        return ASN1_OK;
    }

    BitMerge merge{0, 0, false};
    asn1_err_t rc = collectBitLeaves(node, &merge);
    if (rc != ASN1_OK) {
        return rc;
    }
    if (merge.totalBits == 0) {
        *out_data = nullptr;
        *out_size = 0;
        *out_unused_bits = 0;
        *out_bit_length = 0;
        return ASN1_OK;
    }

    size_t outSize = (merge.totalBits + 7u) / 8u;
    void *buffer = nullptr;
    rc = asn1::documentAllocate(node->document, outSize, &buffer);
    if (rc != ASN1_OK) {
        return rc;
    }
    uint8_t *dst = static_cast<uint8_t *>(buffer);
    std::memset(dst, 0, outSize);
    size_t bitCursor = 0;
    rc = copyBitLeaves(node, dst, &bitCursor);
    if (rc != ASN1_OK) {
        return rc;
    }

    *out_data = dst;
    *out_size = outSize;
    *out_unused_bits =
        static_cast<uint8_t>(outSize * 8u - merge.totalBits);
    *out_bit_length = merge.totalBits;
    return ASN1_OK;
}

extern "C" asn1_err_t asn1_node_get_oid(const asn1_node_t *handle,
                                        const char **out_dotted,
                                        size_t *out_size)
{
    if (handle == nullptr || out_dotted == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    asn1::Node *node = nodeOf(handle);
    if (asn1::universalTagNumber(node) != 6u) {
        return ASN1_E_INVALID_VALUE;
    }
    if (asn1::nodeIsConstructed(node) || node->contentSize == 0 ||
        node->content == nullptr) {
        return ASN1_E_MALFORMED_VALUE;
    }

    if (node->oidText != nullptr) {
        *out_dotted = node->oidText;
        *out_size = std::strlen(node->oidText);
        return ASN1_OK;
    }

    if (node->contentSize > (SIZE_MAX - 8) / 4) {
        return ASN1_E_MEMORY_LIMIT;
    }
    const size_t capacity = node->contentSize * 4 + 8;

    void *buffer = nullptr;
    asn1_err_t rc = asn1::documentAllocate(node->document, capacity, &buffer);
    if (rc != ASN1_OK) {
        return rc;
    }
    char *text = static_cast<char *>(buffer);

    size_t cursor = 0;
    uint64_t first = 0;
    if (!decodeSubidentifier(node->content, node->contentSize, &cursor,
                             &first)) {
        return ASN1_E_MALFORMED_VALUE;
    }

    uint64_t arc0 = 0;
    uint64_t arc1 = 0;
    if (first < 40u) {
        arc0 = 0;
        arc1 = first;
    } else if (first < 80u) {
        arc0 = 1;
        arc1 = first - 40u;
    } else {
        arc0 = 2;
        arc1 = first - 80u;
    }

    size_t written = 0;
    written += appendDecimal(text + written, arc0);
    text[written++] = '.';
    written += appendDecimal(text + written, arc1);

    while (cursor < node->contentSize) {
        uint64_t arc = 0;
        if (!decodeSubidentifier(node->content, node->contentSize, &cursor,
                                 &arc)) {
            return ASN1_E_MALFORMED_VALUE;
        }
        text[written++] = '.';
        written += appendDecimal(text + written, arc);
    }
    text[written] = '\0';

    if (node->document->sealed) {
        node->oidText = text;
    }
    *out_dotted = text;
    *out_size = written;
    return ASN1_OK;
}
