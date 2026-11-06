/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

#include "schema/asn1_schema_encode.h"

#include <cstring>

#include "ber/asn1_ber_decoder.h"
#include "types/asn1_dom.h"

namespace asn1 {
namespace {

const asn1::SchemaType *typeAt(const Schema *schema, uint32_t typeId)
{
    if (schema == nullptr || typeId == 0 || typeId > schema->typeCount) {
        return nullptr;
    }
    return &schema->types[typeId - 1];
}

uint32_t effectiveTagMode(const Schema *schema, const SchemaType *type)
{
    return type->tagMode == ASN1_TAG_MODE_DEFAULT ? schema->moduleTagMode
                                                  : type->tagMode;
}

uint32_t universalTagOf(const SchemaType *type)
{
    switch (type->kind) {
    case ASN1_TYPE_KIND_SEQUENCE:
    case ASN1_TYPE_KIND_SEQUENCE_OF:
        return 16;
    case ASN1_TYPE_KIND_SET:
    case ASN1_TYPE_KIND_SET_OF:
        return 17;
    default:
        return type->tagNumber;
    }
}

void typeTag(const Schema *schema, const SchemaType *type, bool unwrapped,
             uint32_t *outClass, uint32_t *outNumber, bool *outConstructed)
{
    const bool explicitMode =
        !unwrapped && effectiveTagMode(schema, type) == ASN1_TAG_MODE_EXPLICIT;
    if (explicitMode) {
        *outClass = type->tagClass;
        *outNumber = type->tagNumber;
        *outConstructed = true;
        return;
    }
    switch (type->kind) {
    case ASN1_TYPE_KIND_SEQUENCE:
    case ASN1_TYPE_KIND_SEQUENCE_OF:
        *outClass = ASN1_TAG_UNIVERSAL;
        *outNumber = 16;
        *outConstructed = true;
        return;
    case ASN1_TYPE_KIND_SET:
    case ASN1_TYPE_KIND_SET_OF:
        *outClass = ASN1_TAG_UNIVERSAL;
        *outNumber = 17;
        *outConstructed = true;
        return;
    default:
        if (type->tagClass == ASN1_TAG_UNIVERSAL) {
            *outClass = ASN1_TAG_UNIVERSAL;
            *outNumber = universalTagOf(type);
        } else {
            *outClass = type->tagClass;
            *outNumber = type->tagNumber;
        }
        *outConstructed = false;
        return;
    }
}

size_t tagFieldBytes(uint32_t number)
{
    return number < 31 ? 1 : 2;
}

size_t lengthFieldBytes(size_t length)
{
    if (length < 128) {
        return 1;
    }
    size_t bytes = 0;
    size_t remaining = length;
    while (remaining != 0) {
        ++bytes;
        remaining >>= 8;
    }
    return 1 + bytes;
}

void writeTag(uint8_t *dst, uint32_t tagClass, uint32_t tagNumber,
              bool constructed)
{
    uint8_t first = static_cast<uint8_t>((tagClass & 0x3U) << 6);
    if (constructed) {
        first |= 0x20U;
    }
    if (tagNumber < 31) {
        dst[0] = static_cast<uint8_t>(first | tagNumber);
        return;
    }
    dst[0] = static_cast<uint8_t>(first | 0x1FU);
    dst[1] = static_cast<uint8_t>(tagNumber & 0xFFU);
}

size_t writeLength(uint8_t *dst, size_t length)
{
    if (length < 128) {
        dst[0] = static_cast<uint8_t>(length);
        return 1;
    }
    size_t bytes = 0;
    size_t remaining = length;
    while (remaining != 0) {
        ++bytes;
        remaining >>= 8;
    }
    dst[0] = static_cast<uint8_t>(0x80U | bytes);
    for (size_t i = 0; i < bytes; ++i) {
        dst[1 + i] = static_cast<uint8_t>((length >> (8 * (bytes - 1 - i))) &
                                          0xFFU);
    }
    return 1 + bytes;
}

bool rawTlvOf(const Document *doc, const Node *node, const uint8_t **outData,
              size_t *outSize)
{
    if (node->tlvOffset == SIZE_MAX || node->tlvOffset >= doc->inputSize ||
        node->tlvSize > doc->inputSize - node->tlvOffset) {
        return false;
    }
    *outData = doc->input + node->tlvOffset;
    *outSize = node->tlvSize;
    return true;
}

const Node *namedChild(const Node *parent, const char *name)
{
    if (name == nullptr) {
        return nullptr;
    }
    for (const Node *child = parent->firstChild; child != nullptr;
         child = child->nextSibling) {
        if (child->fieldName != nullptr &&
            std::strcmp(child->fieldName, name) == 0) {
            return child;
        }
    }
    return nullptr;
}

bool tagMatches(const Schema *schema, const SchemaType *type, const Node *node,
                bool unwrapped)
{
    if (type->kind == ASN1_TYPE_KIND_ANY) {
        return true;
    }
    if (type->kind == ASN1_TYPE_KIND_CHOICE &&
        effectiveTagMode(schema, type) != ASN1_TAG_MODE_EXPLICIT) {
        for (uint32_t i = 0; i < type->fieldCount; ++i) {
            const SchemaType *branch = typeAt(schema, type->fields[i].typeId);
            if (branch != nullptr && tagMatches(schema, branch, node, false)) {
                return true;
            }
        }
        return false;
    }
    uint32_t cls = 0;
    uint32_t num = 0;
    bool constructed = false;
    typeTag(schema, type, unwrapped, &cls, &num, &constructed);
    return node->tagClass == cls && node->tagNumber == num;
}

int32_t branchIndex(const Schema *schema, const SchemaType *type,
                    const Node *node)
{
    for (uint32_t i = 0; i < type->fieldCount; ++i) {
        const SchemaType *branch = typeAt(schema, type->fields[i].typeId);
        if (branch == nullptr) {
            continue;
        }
        if (node->fieldName != nullptr &&
            type->fields[i].name != nullptr &&
            std::strcmp(node->fieldName, type->fields[i].name) == 0) {
            return static_cast<int32_t>(i);
        }
        if (tagMatches(schema, branch, node, false)) {
            return static_cast<int32_t>(i);
        }
    }
    return -1;
}

bool isDefaultEqual(const Document *doc, const Node *child,
                    const SchemaField &field)
{
    if (field.defaultSize == 0) {
        return false;
    }
    const uint8_t *raw = nullptr;
    size_t rawSize = 0;
    if (!rawTlvOf(doc, child, &raw, &rawSize)) {
        return false;
    }
    return rawSize == field.defaultSize &&
           std::memcmp(raw, field.defaultTlv, rawSize) == 0;
}

struct EncState {
    Context *ctx;
    const Document *doc;
    const Schema *schema;
    const uint8_t *defaultTlv;
    size_t defaultSize;
};

bool sizeOf(const EncState &st, uint32_t typeId, const Node *node,
            bool unwrapped, size_t *outSize, asn1_err_t *outError);

bool validateRetainedDer(Context *ctx, const uint8_t *tlv, size_t size,
                         asn1_err_t *outError);

bool sizeAny(const EncState &st, const SchemaType *type, const Node *node,
             size_t *outSize, asn1_err_t *outError)
{
    /* DEFAULT ANY 的节点就是原始 TLV；EXPLICIT ANY 的节点是外层包装，
       内层 TLV 保存在 content 中。 */
    if (!nodeIsAny(node)) {
        const uint8_t *raw = nullptr;
        size_t rawSize = 0;
        if (!rawTlvOf(st.doc, node, &raw, &rawSize)) {
            *outError = ASN1_E_INVALID_STATE;
            return false;
        }
        if (!validateRetainedDer(st.ctx, raw, rawSize, outError)) {
            return false;
        }
        if (effectiveTagMode(st.schema, type) == ASN1_TAG_MODE_EXPLICIT) {
            const size_t header = tagFieldBytes(type->tagNumber) +
                                  lengthFieldBytes(rawSize);
            *outSize = header + rawSize;
        } else {
            *outSize = rawSize;
        }
        return true;
    }

    const size_t inner = node->contentSize;
    if (effectiveTagMode(st.schema, type) == ASN1_TAG_MODE_EXPLICIT) {
        if (!validateRetainedDer(st.ctx, node->content, inner, outError)) {
            return false;
        }
        const size_t header =
            tagFieldBytes(type->tagNumber) + lengthFieldBytes(inner);
        *outSize = header + inner;
    } else {
        const uint8_t *raw = nullptr;
        size_t rawSize = 0;
        if (!rawTlvOf(st.doc, node, &raw, &rawSize)) {
            *outError = ASN1_E_INVALID_STATE;
            return false;
        }
        if (!validateRetainedDer(st.ctx, raw, rawSize, outError)) {
            return false;
        }
        *outSize = rawSize;
    }
    return true;
}

/* 运行时构树文档的子节点没有字段名；只有这种文档才允许按位置回退。 */
bool hasNamedChildren(const Node *node)
{
    for (const Node *child = node->firstChild; child != nullptr;
         child = child->nextSibling) {
        if (child->fieldName != nullptr) {
            return true;
        }
    }
    return false;
}

/*
 * 保留的原始 TLV（ANY 内层、未知字段）在 schema 感知 DER 编码中必须是
 * 规范 DER。复用解码器的 DER 严格校验，不做隐式重新编码。
 */
bool validateRetainedDer(Context *ctx, const uint8_t *tlv, size_t size,
                         asn1_err_t *outError)
{
    if (tlv == nullptr || size == 0) {
        *outError = ASN1_E_INVALID_STATE;
        return false;
    }
    Document *tmp = nullptr;
    size_t used = 0;
    const asn1_err_t rc =
        decodeBuffer(ctx, tlv, size, ctx->m_maxDepth, false, false,
                     ASN1_ENCODING_DER, &tmp, &used);
    if (rc == ASN1_OK) {
        documentDestroy(tmp);
        return true;
    }
    if (rc == ASN1_E_NOMEM || rc == ASN1_E_MEMORY_LIMIT ||
        rc == ASN1_E_STATIC_POOL_EXHAUSTED) {
        *outError = rc;
        return false;
    }
    *outError = ASN1_E_NON_CANONICAL;
    return false;
}

bool allocateFieldSlots(const EncState &st, uint32_t count,
                        const Node ***outSlots, asn1_err_t *outError)
{
    *outSlots = nullptr;
    if (count == 0) {
        return true;
    }
    void *raw = nullptr;
    if (contextAllocate(st.ctx, static_cast<size_t>(count) * sizeof(const Node *),
                        AllocationKind::kGeneric, &raw) != ASN1_OK) {
        *outError = ASN1_E_NOMEM;
        return false;
    }
    *outSlots = static_cast<const Node **>(raw);
    return true;
}

void releaseFieldSlots(const EncState &st, const Node **slots)
{
    if (slots != nullptr) {
        contextRelease(
            st.ctx,
            const_cast<void *>(reinterpret_cast<const void *>(slots)));
    }
}

/* 为每个 schema 字段找出对应子节点；命名文档按字段名，构树文档按位置。 */
void matchFields(const EncState &st, const SchemaType *type, const Node *node,
                 const Node **slots)
{
    const bool named = hasNamedChildren(node);
    uint32_t positional = 0;
    for (uint32_t i = 0; i < type->fieldCount; ++i) {
        const SchemaField &field = type->fields[i];
        const Node *child = nullptr;
        if (field.name != nullptr) {
            child = namedChild(node, field.name);
        }
        if (child == nullptr && !named) {
            /* 运行时构树文档没有字段名：按子节点顺序回退。 */
            const Node *candidate = node->firstChild;
            for (uint32_t k = 0; candidate != nullptr && k < positional; ++k) {
                candidate = candidate->nextSibling;
            }
            if (candidate != nullptr) {
                const SchemaType *ft = typeAt(st.schema, field.typeId);
                if (ft != nullptr && tagMatches(st.schema, ft, candidate,
                                                false)) {
                    child = candidate;
                    ++positional;
                }
            }
        }
        slots[i] = child;
    }
}

bool isKnownFieldChild(const Node *child, const Node **slots, uint32_t count)
{
    for (uint32_t i = 0; i < count; ++i) {
        if (slots[i] == child) {
            return true;
        }
    }
    return false;
}

bool sumKnownFields(const EncState &st, const SchemaType *type,
                    const Node **slots, size_t *outTotal, asn1_err_t *outError)
{
    size_t total = 0;
    for (uint32_t i = 0; i < type->fieldCount; ++i) {
        const SchemaField &field = type->fields[i];
        const Node *child = slots[i];
        if (child == nullptr) {
            if ((field.flags & ASN1_FIELD_OPTIONAL) != 0 ||
                field.defaultSize != 0) {
                continue;
            }
            *outError = ASN1_E_SCHEMA_FIELD;
            return false;
        }
        if (isDefaultEqual(st.doc, child, field)) {
            continue;
        }
        size_t childSize = 0;
        if (!sizeOf(st, field.typeId, child, false, &childSize, outError)) {
            return false;
        }
        if (total > SIZE_MAX - childSize) {
            *outError = ASN1_E_OUTPUT_LIMIT;
            return false;
        }
        total += childSize;
    }
    *outTotal = total;
    return true;
}

bool addRetainedChild(const EncState &st, const Node *child, size_t *total,
                      asn1_err_t *outError)
{
    const uint8_t *raw = nullptr;
    size_t rawSize = 0;
    if (!rawTlvOf(st.doc, child, &raw, &rawSize)) {
        *outError = ASN1_E_INVALID_STATE;
        return false;
    }
    if (!validateRetainedDer(st.ctx, raw, rawSize, outError)) {
        return false;
    }
    if (rawSize > SIZE_MAX - *total) {
        *outError = ASN1_E_OUTPUT_LIMIT;
        return false;
    }
    *total += rawSize;
    return true;
}

/* SEQUENCE：已知字段按 schema 顺序，未知字段按 DOM 原序追加。 */
bool sizeSequenceFields(const EncState &st, const SchemaType *type,
                        const Node *node, size_t *outContent,
                        asn1_err_t *outError)
{
    const Node **slots = nullptr;
    if (!allocateFieldSlots(st, type->fieldCount, &slots, outError)) {
        return false;
    }
    matchFields(st, type, node, slots);
    size_t total = 0;
    bool ok = sumKnownFields(st, type, slots, &total, outError);
    if (ok) {
        for (const Node *child = node->firstChild; child != nullptr;
             child = child->nextSibling) {
            if (isKnownFieldChild(child, slots, type->fieldCount)) {
                continue;
            }
            if (!addRetainedChild(st, child, &total, outError)) {
                ok = false;
                break;
            }
        }
    }
    releaseFieldSlots(st, slots);
    if (!ok) {
        return false;
    }
    *outContent = total;
    return true;
}

/* SET：不做已知/未知合并排序；未知字段直接拒绝，绝不产出非法 DER。 */
bool sizeSetFields(const EncState &st, const SchemaType *type, const Node *node,
                   size_t *outContent, asn1_err_t *outError)
{
    const Node **slots = nullptr;
    if (!allocateFieldSlots(st, type->fieldCount, &slots, outError)) {
        return false;
    }
    matchFields(st, type, node, slots);
    size_t total = 0;
    bool ok = sumKnownFields(st, type, slots, &total, outError);
    if (ok) {
        for (const Node *child = node->firstChild; child != nullptr;
             child = child->nextSibling) {
            if (!isKnownFieldChild(child, slots, type->fieldCount)) {
                *outError = ASN1_E_SCHEMA_FIELD;
                ok = false;
                break;
            }
        }
    }
    releaseFieldSlots(st, slots);
    if (!ok) {
        return false;
    }
    *outContent = total;
    return true;
}

bool sizeOf(const EncState &st, uint32_t typeId, const Node *node,
            bool unwrapped, size_t *outSize, asn1_err_t *outError)
{
    const SchemaType *type = typeAt(st.schema, typeId);
    if (type == nullptr || node == nullptr) {
        *outError = ASN1_E_INVALID_STATE;
        return false;
    }
    if (type->kind == ASN1_TYPE_KIND_ANY) {
        return sizeAny(st, type, node, outSize, outError);
    }
    if (!unwrapped &&
        effectiveTagMode(st.schema, type) == ASN1_TAG_MODE_EXPLICIT) {
        if (node->firstChild == nullptr ||
            node->firstChild->nextSibling != nullptr) {
            *outError = ASN1_E_INVALID_STATE;
            return false;
        }
        size_t base = 0;
        if (!sizeOf(st, typeId, node->firstChild, true, &base, outError)) {
            return false;
        }
        const size_t header = tagFieldBytes(type->tagNumber) +
                              lengthFieldBytes(base);
        *outSize = header + base;
        return true;
    }
    if (type->kind == ASN1_TYPE_KIND_CHOICE) {
        const int32_t index = branchIndex(st.schema, type, node);
        if (index < 0) {
            *outError = ASN1_E_SCHEMA_TYPE;
            return false;
        }
        return sizeOf(st, type->fields[index].typeId, node, false, outSize,
                      outError);
    }

    size_t content = 0;
    if (type->kind == ASN1_TYPE_KIND_SEQUENCE) {
        if (!sizeSequenceFields(st, type, node, &content, outError)) {
            return false;
        }
    } else if (type->kind == ASN1_TYPE_KIND_SET) {
        if (!sizeSetFields(st, type, node, &content, outError)) {
            return false;
        }
    } else if (type->kind == ASN1_TYPE_KIND_SEQUENCE_OF ||
               type->kind == ASN1_TYPE_KIND_SET_OF) {
        for (const Node *child = node->firstChild; child != nullptr;
             child = child->nextSibling) {
            size_t childSize = 0;
            if (!sizeOf(st, type->elementTypeId, child, false, &childSize,
                        outError)) {
                return false;
            }
            if (content > SIZE_MAX - childSize) {
                *outError = ASN1_E_OUTPUT_LIMIT;
                return false;
            }
            content += childSize;
        }
    } else if ((node->flags & kNodeFlagConstructed) != 0) {
        for (const Node *child = node->firstChild; child != nullptr;
             child = child->nextSibling) {
            const uint8_t *raw = nullptr;
            size_t rawSize = 0;
            if (!rawTlvOf(st.doc, child, &raw, &rawSize)) {
                *outError = ASN1_E_INVALID_STATE;
                return false;
            }
            if (content > SIZE_MAX - rawSize) {
                *outError = ASN1_E_OUTPUT_LIMIT;
                return false;
            }
            content += rawSize;
        }
    } else {
        content = node->contentSize;
    }

    uint32_t cls = 0;
    uint32_t num = 0;
    bool constructed = false;
    typeTag(st.schema, type, unwrapped, &cls, &num, &constructed);
    (void)cls;
    if (unwrapped && type->kind == ASN1_TYPE_KIND_SIMPLE &&
        effectiveTagMode(st.schema, type) == ASN1_TAG_MODE_EXPLICIT) {
        /* 描述表只记录 EXPLICIT 外层标签，内层通用标签不可知，
           按 DOM 节点自身的标签写出。 */
        num = node->tagNumber;
    }
    const size_t header = tagFieldBytes(num) + lengthFieldBytes(content);
    if (content > SIZE_MAX - header) {
        *outError = ASN1_E_OUTPUT_LIMIT;
        return false;
    }
    *outSize = header + content;
    return true;
}

bool writeOf(const EncState &st, uint32_t typeId, const Node *node,
             bool unwrapped, uint8_t *dst, size_t capacity, size_t *outUsed,
             asn1_err_t *outError);

bool writeTaggedContent(const EncState &st, uint32_t tagClass,
                        uint32_t tagNumber, bool constructed,
                        const uint8_t *content, size_t contentSize,
                        uint8_t *dst, size_t capacity, size_t *outUsed,
                        asn1_err_t *outError)
{
    (void)st;
    const size_t header = tagFieldBytes(tagNumber) +
                          lengthFieldBytes(contentSize);
    if (header + contentSize > capacity) {
        *outError = ASN1_E_OUTPUT_LIMIT;
        return false;
    }
    writeTag(dst, tagClass, tagNumber, constructed);
    const size_t lengthBytes = writeLength(dst + tagFieldBytes(tagNumber),
                                           contentSize);
    if (header != tagFieldBytes(tagNumber) + lengthBytes) {
        *outError = ASN1_E_INVALID_STATE;
        return false;
    }
    if (contentSize != 0) {
        std::memcpy(dst + header, content, contentSize);
    }
    *outUsed = header + contentSize;
    return true;
}

void writeSorted(const uint8_t *buffer, size_t *offsets, size_t *sizes,
                 size_t count)
{
    /* 插入排序：按完整 TLV 字节序升序。 */
    for (size_t i = 1; i < count; ++i) {
        size_t j = i;
        while (j > 0) {
            const size_t a = offsets[j - 1];
            const size_t b = offsets[j];
            const size_t na = sizes[j - 1];
            const size_t nb = sizes[j];
            const uint8_t *pa = buffer + a;
            const uint8_t *pb = buffer + b;
            const size_t compare = na < nb ? na : nb;
            int order = 0;
            for (size_t k = 0; k < compare; ++k) {
                if (pa[k] != pb[k]) {
                    order = pa[k] < pb[k] ? -1 : 1;
                    break;
                }
            }
            if (order == 0) {
                order = na < nb ? -1 : (na > nb ? 1 : 0);
            }
            if (order <= 0) {
                break;
            }
            const size_t tmpOffset = offsets[j - 1];
            offsets[j - 1] = offsets[j];
            offsets[j] = tmpOffset;
            const size_t tmpSize = sizes[j - 1];
            sizes[j - 1] = sizes[j];
            sizes[j] = tmpSize;
            --j;
        }
    }
}

bool writeSetOf(const EncState &st, uint32_t typeId, const Node *node,
                uint8_t *dst, size_t capacity, size_t *outUsed,
                asn1_err_t *outError)
{
    size_t count = 0;
    size_t total = 0;
    for (const Node *child = node->firstChild; child != nullptr;
         child = child->nextSibling) {
        size_t childSize = 0;
        if (!sizeOf(st, typeId, child, false, &childSize, outError)) {
            return false;
        }
        total += childSize;
        ++count;
    }
    const size_t header =
        tagFieldBytes(17) + lengthFieldBytes(total);
    if (header + total > capacity) {
        *outError = ASN1_E_OUTPUT_LIMIT;
        return false;
    }
    if (count == 0) {
        writeTag(dst, ASN1_TAG_UNIVERSAL, 17, true);
        writeLength(dst + 1, 0);
        *outUsed = header;
        return true;
    }

    void *tempRaw = nullptr;
    void *offsetRaw = nullptr;
    void *sizeRaw = nullptr;
    if (contextAllocate(st.ctx, total, AllocationKind::kGeneric, &tempRaw) !=
            ASN1_OK ||
        contextAllocate(st.ctx, count * sizeof(size_t),
                        AllocationKind::kGeneric, &offsetRaw) != ASN1_OK ||
        contextAllocate(st.ctx, count * sizeof(size_t),
                        AllocationKind::kGeneric, &sizeRaw) != ASN1_OK) {
        if (tempRaw != nullptr) {
            contextRelease(st.ctx, tempRaw);
        }
        if (offsetRaw != nullptr) {
            contextRelease(st.ctx, offsetRaw);
        }
        *outError = ASN1_E_NOMEM;
        return false;
    }
    uint8_t *temp = static_cast<uint8_t *>(tempRaw);
    size_t *offsets = static_cast<size_t *>(offsetRaw);
    size_t *sizes = static_cast<size_t *>(sizeRaw);
    size_t cursor = 0;
    size_t index = 0;
    for (const Node *child = node->firstChild; child != nullptr;
         child = child->nextSibling) {
        offsets[index] = cursor;
        size_t used = 0;
        if (!writeOf(st, typeId, child, false, temp + cursor, total - cursor,
                     &used, outError)) {
            contextRelease(st.ctx, sizeRaw);
            contextRelease(st.ctx, offsetRaw);
            contextRelease(st.ctx, tempRaw);
            return false;
        }
        sizes[index] = used;
        cursor += used;
        ++index;
    }
    writeSorted(temp, offsets, sizes, count);

    writeTag(dst, ASN1_TAG_UNIVERSAL, 17, true);
    writeLength(dst + 1, total);
    size_t pos = header;
    for (size_t i = 0; i < count; ++i) {
        std::memcpy(dst + pos, temp + offsets[i], sizes[i]);
        pos += sizes[i];
    }
    contextRelease(st.ctx, sizeRaw);
    contextRelease(st.ctx, offsetRaw);
    contextRelease(st.ctx, tempRaw);
    *outUsed = pos;
    return true;
}

/* SEQUENCE：已知字段按 schema 顺序，未知字段按 DOM 原序追加。 */
bool writeSequenceFields(const EncState &st, const SchemaType *type,
                         const Node *node, uint8_t *dst, size_t capacity,
                         size_t *outUsed, asn1_err_t *outError)
{
    const Node **slots = nullptr;
    if (!allocateFieldSlots(st, type->fieldCount, &slots, outError)) {
        return false;
    }
    matchFields(st, type, node, slots);
    size_t pos = 0;
    bool ok = true;
    for (uint32_t i = 0; i < type->fieldCount && ok; ++i) {
        const SchemaField &field = type->fields[i];
        const Node *child = slots[i];
        if (child == nullptr) {
            if ((field.flags & ASN1_FIELD_OPTIONAL) != 0 ||
                field.defaultSize != 0) {
                continue;
            }
            *outError = ASN1_E_SCHEMA_FIELD;
            ok = false;
            break;
        }
        if (isDefaultEqual(st.doc, child, field)) {
            continue;
        }
        size_t used = 0;
        if (!writeOf(st, field.typeId, child, false, dst + pos, capacity - pos,
                     &used, outError)) {
            ok = false;
            break;
        }
        pos += used;
    }
    if (ok) {
        for (const Node *child = node->firstChild; child != nullptr;
             child = child->nextSibling) {
            if (isKnownFieldChild(child, slots, type->fieldCount)) {
                continue;
            }
            const uint8_t *raw = nullptr;
            size_t rawSize = 0;
            if (!rawTlvOf(st.doc, child, &raw, &rawSize)) {
                *outError = ASN1_E_INVALID_STATE;
                ok = false;
                break;
            }
            if (rawSize > capacity - pos) {
                *outError = ASN1_E_OUTPUT_LIMIT;
                ok = false;
                break;
            }
            std::memcpy(dst + pos, raw, rawSize);
            pos += rawSize;
        }
    }
    releaseFieldSlots(st, slots);
    if (!ok) {
        return false;
    }
    *outUsed = pos;
    return true;
}

/* SET：已知字段参与 DER 标签排序；出现未知字段直接拒绝。 */
bool writeSet(const EncState &st, const SchemaType *type, const Node *node,
              uint32_t cls, uint32_t num, uint8_t *dst, size_t capacity,
              size_t *outUsed, asn1_err_t *outError)
{
    const Node **slots = nullptr;
    if (!allocateFieldSlots(st, type->fieldCount, &slots, outError)) {
        return false;
    }
    matchFields(st, type, node, slots);

    bool ok = true;
    for (const Node *child = node->firstChild; child != nullptr;
         child = child->nextSibling) {
        if (!isKnownFieldChild(child, slots, type->fieldCount)) {
            *outError = ASN1_E_SCHEMA_FIELD;
            ok = false;
            break;
        }
    }

    size_t fieldTotal = 0;
    uint32_t count = 0;
    for (uint32_t i = 0; i < type->fieldCount && ok; ++i) {
        const SchemaField &field = type->fields[i];
        const Node *child = slots[i];
        if (child == nullptr) {
            if ((field.flags & ASN1_FIELD_OPTIONAL) != 0 ||
                field.defaultSize != 0) {
                continue;
            }
            *outError = ASN1_E_SCHEMA_FIELD;
            ok = false;
            break;
        }
        if (isDefaultEqual(st.doc, child, field)) {
            continue;
        }
        size_t childSize = 0;
        if (!sizeOf(st, field.typeId, child, false, &childSize, outError)) {
            ok = false;
            break;
        }
        if (fieldTotal > SIZE_MAX - childSize) {
            *outError = ASN1_E_OUTPUT_LIMIT;
            ok = false;
            break;
        }
        fieldTotal += childSize;
        ++count;
    }

    const size_t header = tagFieldBytes(num) + lengthFieldBytes(fieldTotal);
    if (ok && header + fieldTotal > capacity) {
        *outError = ASN1_E_OUTPUT_LIMIT;
        ok = false;
    }
    if (ok) {
        writeTag(dst, cls, num, true);
        writeLength(dst + tagFieldBytes(num), fieldTotal);
        if (fieldTotal == 0) {
            *outUsed = header;
        } else {
            void *tempRaw = nullptr;
            void *offsetRaw = nullptr;
            void *sizeRaw = nullptr;
            if (contextAllocate(st.ctx, fieldTotal,
                                AllocationKind::kGeneric, &tempRaw) !=
                    ASN1_OK ||
                contextAllocate(st.ctx, count * sizeof(size_t),
                                AllocationKind::kGeneric, &offsetRaw) !=
                    ASN1_OK ||
                contextAllocate(st.ctx, count * sizeof(size_t),
                                AllocationKind::kGeneric, &sizeRaw) !=
                    ASN1_OK) {
                if (tempRaw != nullptr) {
                    contextRelease(st.ctx, tempRaw);
                }
                if (offsetRaw != nullptr) {
                    contextRelease(st.ctx, offsetRaw);
                }
                *outError = ASN1_E_NOMEM;
                ok = false;
            } else {
                uint8_t *temp = static_cast<uint8_t *>(tempRaw);
                size_t *offsets = static_cast<size_t *>(offsetRaw);
                size_t *sizes = static_cast<size_t *>(sizeRaw);
                size_t cursor = 0;
                size_t index = 0;
                for (uint32_t i = 0; i < type->fieldCount; ++i) {
                    const Node *child = slots[i];
                    if (child == nullptr ||
                        isDefaultEqual(st.doc, child, type->fields[i])) {
                        continue;
                    }
                    offsets[index] = cursor;
                    size_t used = 0;
                    if (!writeOf(st, type->fields[i].typeId, child, false,
                                 temp + cursor, fieldTotal - cursor, &used,
                                 outError)) {
                        ok = false;
                        break;
                    }
                    sizes[index] = used;
                    cursor += used;
                    ++index;
                }
                if (ok) {
                    writeSorted(temp, offsets, sizes, count);
                    size_t pos = header;
                    for (size_t i = 0; i < count; ++i) {
                        std::memcpy(dst + pos, temp + offsets[i], sizes[i]);
                        pos += sizes[i];
                    }
                    *outUsed = pos;
                }
                contextRelease(st.ctx, sizeRaw);
                contextRelease(st.ctx, offsetRaw);
                contextRelease(st.ctx, tempRaw);
            }
        }
    }
    releaseFieldSlots(st, slots);
    return ok;
}

bool writeAny(const EncState &st, const SchemaType *type, const Node *node,
              uint8_t *dst, size_t capacity, size_t *outUsed,
              asn1_err_t *outError)
{
    const bool explicitMode =
        effectiveTagMode(st.schema, type) == ASN1_TAG_MODE_EXPLICIT;
    const uint8_t *raw = nullptr;
    size_t rawSize = 0;
    if (!rawTlvOf(st.doc, node, &raw, &rawSize)) {
        *outError = ASN1_E_INVALID_STATE;
        return false;
    }

    if (explicitMode) {
        /* 内层原始 TLV 由 content 承载；按 schema 重新加外层包装。 */
        const uint8_t *inner = nodeIsAny(node) ? node->content : raw;
        const size_t innerSize = nodeIsAny(node) ? node->contentSize : rawSize;
        return writeTaggedContent(st, type->tagClass, type->tagNumber, true,
                                  inner, innerSize, dst, capacity, outUsed,
                                  outError);
    }
    if (rawSize > capacity) {
        *outError = ASN1_E_OUTPUT_LIMIT;
        return false;
    }
    std::memcpy(dst, raw, rawSize);
    *outUsed = rawSize;
    return true;
}

bool writeOf(const EncState &st, uint32_t typeId, const Node *node,
             bool unwrapped, uint8_t *dst, size_t capacity, size_t *outUsed,
             asn1_err_t *outError)
{
    const SchemaType *type = typeAt(st.schema, typeId);
    if (type == nullptr || node == nullptr) {
        *outError = ASN1_E_INVALID_STATE;
        return false;
    }
    if (type->kind == ASN1_TYPE_KIND_ANY) {
        return writeAny(st, type, node, dst, capacity, outUsed, outError);
    }
    if (!unwrapped &&
        effectiveTagMode(st.schema, type) == ASN1_TAG_MODE_EXPLICIT) {
        if (node->firstChild == nullptr ||
            node->firstChild->nextSibling != nullptr) {
            *outError = ASN1_E_INVALID_STATE;
            return false;
        }
        size_t base = 0;
        if (!sizeOf(st, typeId, node->firstChild, true, &base, outError)) {
            return false;
        }
        const size_t header = tagFieldBytes(type->tagNumber) +
                              lengthFieldBytes(base);
        if (header + base > capacity) {
            *outError = ASN1_E_OUTPUT_LIMIT;
            return false;
        }
        writeTag(dst, type->tagClass, type->tagNumber, true);
        writeLength(dst + tagFieldBytes(type->tagNumber), base);
        size_t used = 0;
        if (!writeOf(st, typeId, node->firstChild, true, dst + header,
                     capacity - header, &used, outError)) {
            return false;
        }
        *outUsed = header + used;
        return true;
    }
    if (type->kind == ASN1_TYPE_KIND_CHOICE) {
        const int32_t index = branchIndex(st.schema, type, node);
        if (index < 0) {
            *outError = ASN1_E_SCHEMA_TYPE;
            return false;
        }
        return writeOf(st, type->fields[index].typeId, node, false, dst,
                       capacity, outUsed, outError);
    }
    if (type->kind == ASN1_TYPE_KIND_SET_OF) {
        return writeSetOf(st, type->elementTypeId, node, dst, capacity, outUsed,
                          outError);
    }

    size_t content = 0;
    if (!sizeOf(st, typeId, node, unwrapped, &content, outError)) {
        return false;
    }
    uint32_t cls = 0;
    uint32_t num = 0;
    bool constructed = false;
    typeTag(st.schema, type, unwrapped, &cls, &num, &constructed);
    if (unwrapped && type->kind == ASN1_TYPE_KIND_SIMPLE &&
        effectiveTagMode(st.schema, type) == ASN1_TAG_MODE_EXPLICIT) {
        /* 与 sizeOf 保持一致：内层通用标签取自 DOM 节点。 */
        cls = node->tagClass;
        num = node->tagNumber;
        constructed = false;
    }

    if (type->kind == ASN1_TYPE_KIND_SET) {
        return writeSet(st, type, node, cls, num, dst, capacity, outUsed,
                        outError);
    }
    if (type->kind == ASN1_TYPE_KIND_SEQUENCE_OF) {
        /* 顺序编码子元素。content 需按子元素 TLV 之和计算，不能复用
           sizeOf（其结果已包含本层标签/长度头）。 */
        size_t seqContent = 0;
        for (const Node *child = node->firstChild; child != nullptr;
             child = child->nextSibling) {
            size_t childSize = 0;
            if (!sizeOf(st, type->elementTypeId, child, false, &childSize,
                        outError)) {
                return false;
            }
            if (seqContent > SIZE_MAX - childSize) {
                *outError = ASN1_E_OUTPUT_LIMIT;
                return false;
            }
            seqContent += childSize;
        }
        const size_t header =
            tagFieldBytes(num) + lengthFieldBytes(seqContent);
        if (header + seqContent > capacity) {
            *outError = ASN1_E_OUTPUT_LIMIT;
            return false;
        }
        writeTag(dst, cls, num, constructed);
        writeLength(dst + tagFieldBytes(num), seqContent);
        size_t pos = header;
        for (const Node *child = node->firstChild; child != nullptr;
             child = child->nextSibling) {
            size_t used = 0;
            if (!writeOf(st, type->elementTypeId, child, false, dst + pos,
                         capacity - pos, &used, outError)) {
                return false;
            }
            pos += used;
        }
        *outUsed = pos;
        return true;
    }
    if (type->kind == ASN1_TYPE_KIND_SEQUENCE) {
        /* SEQUENCE：已知字段按 schema 顺序，未知字段按 DOM 原序追加。 */
        size_t fieldTotal = 0;
        if (!sizeSequenceFields(st, type, node, &fieldTotal, outError)) {
            return false;
        }
        const size_t header =
            tagFieldBytes(num) + lengthFieldBytes(fieldTotal);
        if (header + fieldTotal > capacity) {
            *outError = ASN1_E_OUTPUT_LIMIT;
            return false;
        }
        writeTag(dst, cls, num, constructed);
        writeLength(dst + tagFieldBytes(num), fieldTotal);
        size_t inner = 0;
        if (!writeSequenceFields(st, type, node, dst + header, fieldTotal,
                                 &inner, outError)) {
            return false;
        }
        *outUsed = header + inner;
        return true;
    }

    if (type->kind != ASN1_TYPE_KIND_SIMPLE) {
        *outError = ASN1_E_INVALID_STATE;
        return false;
    }

    if ((node->flags & kNodeFlagConstructed) != 0) {
        const size_t header = tagFieldBytes(num) + lengthFieldBytes(content);
        if (header + content > capacity) {
            *outError = ASN1_E_OUTPUT_LIMIT;
            return false;
        }
        writeTag(dst, cls, num, true);
        writeLength(dst + tagFieldBytes(num), content);
        size_t pos = header;
        for (const Node *child = node->firstChild; child != nullptr;
             child = child->nextSibling) {
            const uint8_t *raw = nullptr;
            size_t rawSize = 0;
            if (!rawTlvOf(st.doc, child, &raw, &rawSize)) {
                *outError = ASN1_E_INVALID_STATE;
                return false;
            }
            if (rawSize > capacity - pos) {
                *outError = ASN1_E_OUTPUT_LIMIT;
                return false;
            }
            std::memcpy(dst + pos, raw, rawSize);
            pos += rawSize;
        }
        *outUsed = pos;
        return true;
    }
    return writeTaggedContent(st, cls, num, false, node->content,
                              node->contentSize, dst, capacity, outUsed,
                              outError);
}

} /* namespace */

asn1_err_t schemaMeasureDocument(Context *ctx, const Document *doc,
                                 const Schema *schema, size_t *outSize) noexcept
{
    if (ctx == nullptr || doc == nullptr || doc->root == nullptr ||
        schema == nullptr || !schema->sealed || schema->rootTypeId == 0 ||
        outSize == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    EncState st;
    st.ctx = ctx;
    st.doc = doc;
    st.schema = schema;
    st.defaultTlv = nullptr;
    st.defaultSize = 0;
    size_t size = 0;
    asn1_err_t error = ASN1_OK;
    if (!sizeOf(st, schema->rootTypeId, doc->root, false, &size, &error)) {
        contextSetError(ctx, error, SIZE_MAX, 0);
        return error;
    }
    *outSize = size;
    return ASN1_OK;
}

asn1_err_t schemaEncodeDocument(Context *ctx, const Document *doc,
                                const Schema *schema, uint8_t *dst,
                                size_t capacity) noexcept
{
    if (ctx == nullptr || doc == nullptr || doc->root == nullptr ||
        schema == nullptr || dst == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    EncState st;
    st.ctx = ctx;
    st.doc = doc;
    st.schema = schema;
    st.defaultTlv = nullptr;
    st.defaultSize = 0;
    size_t total = 0;
    asn1_err_t error = ASN1_OK;
    size_t used = 0;
    if (!sizeOf(st, schema->rootTypeId, doc->root, false, &total, &error)) {
        contextSetError(ctx, error, SIZE_MAX, 0);
        return error;
    }
    if (total > capacity) {
        contextSetError(ctx, ASN1_E_OUTPUT_LIMIT, SIZE_MAX, 0);
        return ASN1_E_OUTPUT_LIMIT;
    }
    if (!writeOf(st, schema->rootTypeId, doc->root, false, dst, capacity, &used,
                 &error)) {
        contextSetError(ctx, error, SIZE_MAX, 0);
        return error;
    }
    if (used != total) {
        contextSetError(ctx, ASN1_E_INVALID_STATE, SIZE_MAX, 0);
        return ASN1_E_INVALID_STATE;
    }
    return ASN1_OK;
}

} /* namespace asn1 */
