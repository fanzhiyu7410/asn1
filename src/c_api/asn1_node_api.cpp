/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 节点只读访问与原始内容读取。
 *
 * 职责：把 C 句柄转换为内部 Node/Document，并提供无分配的元数据访问。
 * 依赖：types/asn1_dom.h。
 */

// ============================================================================
// 依赖与前置声明
// ============================================================================

#include <asn1/asn1.h>

#include <cstring>

#include "types/asn1_dom.h"

namespace {

asn1::Document *documentOf(const asn1_doc_t *handle) noexcept
{
    return const_cast<asn1::Document *>(
        static_cast<const asn1::Document *>(static_cast<const void *>(handle)));
}

const asn1::Node *nodeOf(const asn1_node_t *handle) noexcept
{
    return static_cast<const asn1::Node *>(static_cast<const void *>(handle));
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

// 节点没有独立生命周期。

// ============================================================================
// 公共接口
// ============================================================================

extern "C" const asn1_node_t *asn1_doc_root(const asn1_doc_t *handle)
{
    if (handle == nullptr) {
        return nullptr;
    }
    asn1::Document *doc = documentOf(handle);
    if (doc->magic != asn1::kDocumentMagic) {
        return nullptr;
    }
    return reinterpret_cast<const asn1_node_t *>(doc->root);
}

extern "C" asn1_encoding_t asn1_doc_source_encoding(const asn1_doc_t *handle)
{
    if (handle == nullptr) {
        return ASN1_ENCODING_NONE;
    }
    asn1::Document *doc = documentOf(handle);
    if (doc->magic != asn1::kDocumentMagic) {
        return ASN1_ENCODING_NONE;
    }
    return doc->encoding;
}

extern "C" asn1_tag_class_t asn1_node_tag_class(const asn1_node_t *handle)
{
    const asn1::Node *node = nodeOf(handle);
    if (node == nullptr) {
        return ASN1_TAG_UNIVERSAL;
    }
    return static_cast<asn1_tag_class_t>(node->tagClass);
}

extern "C" uint32_t asn1_node_tag_number(const asn1_node_t *handle)
{
    const asn1::Node *node = nodeOf(handle);
    return node == nullptr ? 0 : node->tagNumber;
}

extern "C" asn1_encoding_form_t asn1_node_encoding_form(
    const asn1_node_t *handle)
{
    const asn1::Node *node = nodeOf(handle);
    if (node == nullptr) {
        return ASN1_FORM_PRIMITIVE;
    }
    return asn1::nodeIsConstructed(node) ? ASN1_FORM_CONSTRUCTED
                                         : ASN1_FORM_PRIMITIVE;
}

extern "C" int asn1_node_is_indefinite(const asn1_node_t *handle)
{
    const asn1::Node *node = nodeOf(handle);
    if (node == nullptr) {
        return 0;
    }
    return (node->flags & asn1::kNodeFlagIndefinite) != 0 ? 1 : 0;
}

extern "C" size_t asn1_node_child_count(const asn1_node_t *handle)
{
    return asn1::nodeChildCount(nodeOf(handle));
}

extern "C" const asn1_node_t *asn1_node_child_at(const asn1_node_t *handle,
                                                 size_t index)
{
    const asn1::Node *node = nodeOf(handle);
    if (node == nullptr || asn1::nodeIsAny(node)) {
        /* ANY 节点不展开，子节点访问一律返回 NULL。 */
        return nullptr;
    }
    const asn1::Node *child = node->firstChild;
    size_t current = 0;
    while (child != nullptr) {
        if (current == index) {
            return reinterpret_cast<const asn1_node_t *>(child);
        }
        ++current;
        child = child->nextSibling;
    }
    return nullptr;
}

extern "C" const asn1_node_t *asn1_node_child_by_name(
    const asn1_node_t *handle, const char *field_name)
{
    const asn1::Node *node = nodeOf(handle);
    if (node == nullptr || field_name == nullptr || asn1::nodeIsAny(node)) {
        return nullptr;
    }
    for (const asn1::Node *child = node->firstChild; child != nullptr;
         child = child->nextSibling) {
        if (child->fieldName != nullptr &&
            std::strcmp(child->fieldName, field_name) == 0) {
            return reinterpret_cast<const asn1_node_t *>(child);
        }
    }
    return nullptr;
}

extern "C" const char *asn1_node_field_name(const asn1_node_t *handle)
{
    const asn1::Node *node = nodeOf(handle);
    return node == nullptr ? nullptr : node->fieldName;
}

extern "C" const asn1_node_t *asn1_node_parent(const asn1_node_t *handle)
{
    const asn1::Node *node = nodeOf(handle);
    if (node == nullptr || node->parent == nullptr) {
        return nullptr;
    }
    return reinterpret_cast<const asn1_node_t *>(node->parent);
}

extern "C" asn1_err_t asn1_node_content(const asn1_node_t *handle,
                                        const uint8_t **out_data,
                                        size_t *out_size)
{
    if (handle == nullptr || out_data == nullptr || out_size == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    const asn1::Node *node = nodeOf(handle);
    if (asn1::nodeIsAny(node)) {
        /* ANY 返回原始内容字节（不含 tag/len），构造型同样返回切片。 */
        *out_data = node->content;
        *out_size = node->contentSize;
        return ASN1_OK;
    }
    if (asn1::nodeIsConstructed(node)) {
        return ASN1_E_INVALID_STATE;
    }

    *out_data = node->content;
    *out_size = node->contentSize;
    return ASN1_OK;
}

extern "C" const uint8_t *asn1_node_tlv(const asn1_node_t *handle,
                                        size_t *out_size)
{
    if (out_size != nullptr) {
        *out_size = 0;
    }
    const asn1::Node *node = nodeOf(handle);
    if (node == nullptr || node->document == nullptr) {
        return nullptr;
    }
    if (asn1::nodeIsAny(node) && node->rawTlv != nullptr) {
        /* ANY 的原始完整 TLV 独立于文档输入缓冲保存。 */
        if (out_size != nullptr) {
            *out_size = node->rawTlvSize;
        }
        return node->rawTlv;
    }
    if (node->tlvOffset == SIZE_MAX || node->document->input == nullptr) {
        /* runtime 构树节点没有原始 TLV。 */
        return nullptr;
    }
    if (out_size != nullptr) {
        *out_size = node->tlvSize;
    }
    return node->document->input + node->tlvOffset;
}

extern "C" size_t asn1_node_offset(const asn1_node_t *handle)
{
    const asn1::Node *node = nodeOf(handle);
    if (node == nullptr || node->tlvOffset == SIZE_MAX) {
        return SIZE_MAX;
    }
    return node->tlvOffset;
}
