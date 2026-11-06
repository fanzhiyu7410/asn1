/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * schema 感知解码与文档校验。
 *
 * 职责：在 BER/DER 解析出的 DOM 上按 schema 绑定类型与字段、保留 ANY
 *       原始 TLV、求值约束，并按选项处理未知字段；同时提供
 *       asn1_doc_validate 复用同一套校验逻辑（不修改节点）。
 * 依赖：ber/asn1_ber_decoder.h、core/asn1_context.h、schema/asn1_schema.h、
 *       types/asn1_dom.h。
 * 所有权：不创建新文档；字段名复制进现有文档 arena；ANY 原始 TLV 指向
 *         文档输入切片（借用或已复制）。
 */

#include <asn1/asn1.h>

#include <cstdio>
#include <cstring>

#include "ber/asn1_ber_decoder.h"
#include "core/asn1_context.h"
#include "schema/asn1_schema.h"
#include "types/asn1_dom.h"

namespace {

constexpr size_t kPathBytes = 256;
constexpr size_t kDecimalDigits = 2048;

const asn1::SchemaType *typeAt(const asn1::Schema *schema, uint32_t typeId)
{
    if (schema == nullptr || typeId == 0 || typeId > schema->typeCount) {
        return nullptr;
    }
    return &schema->types[typeId - 1];
}

uint32_t effectiveTagMode(const asn1::Schema *schema,
                          const asn1::SchemaType *type)
{
    if (type->tagMode == ASN1_TAG_MODE_DEFAULT) {
        return schema->moduleTagMode;
    }
    return type->tagMode;
}

uint32_t universalTagOf(const asn1::SchemaType *type)
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

/* 计算类型的期望标签；CHOICE（无外层包装）返回 false 表示由分支决定。 */
bool expectedTag(const asn1::Schema *schema, const asn1::SchemaType *type,
                 bool unwrapped, uint32_t *outClass, uint32_t *outNumber)
{
    if (type->kind == ASN1_TYPE_KIND_CHOICE &&
        effectiveTagMode(schema, type) != ASN1_TAG_MODE_EXPLICIT) {
        return false;
    }
    if (!unwrapped &&
        effectiveTagMode(schema, type) == ASN1_TAG_MODE_EXPLICIT) {
        *outClass = type->tagClass;
        *outNumber = type->tagNumber;
        return true;
    }
    /* 剥离显式包装后，内层始终回到通用 SEQUENCE/SET 标签。 */
    if (unwrapped) {
        if (type->kind == ASN1_TYPE_KIND_SEQUENCE ||
            type->kind == ASN1_TYPE_KIND_SEQUENCE_OF) {
            *outClass = ASN1_TAG_UNIVERSAL;
            *outNumber = 16;
            return true;
        }
        if (type->kind == ASN1_TYPE_KIND_SET ||
            type->kind == ASN1_TYPE_KIND_SET_OF) {
            *outClass = ASN1_TAG_UNIVERSAL;
            *outNumber = 17;
            return true;
        }
    }
    /* IMPLICIT 覆盖的构造类型改用类型自身的非通用标签。 */
    if (type->kind == ASN1_TYPE_KIND_SEQUENCE ||
        type->kind == ASN1_TYPE_KIND_SEQUENCE_OF) {
        *outClass = type->tagClass;
        *outNumber =
            type->tagClass == ASN1_TAG_UNIVERSAL ? 16 : type->tagNumber;
        return true;
    }
    if (type->kind == ASN1_TYPE_KIND_SET ||
        type->kind == ASN1_TYPE_KIND_SET_OF) {
        *outClass = type->tagClass;
        *outNumber =
            type->tagClass == ASN1_TAG_UNIVERSAL ? 17 : type->tagNumber;
        return true;
    }
    if (type->tagClass == ASN1_TAG_UNIVERSAL) {
        *outClass = ASN1_TAG_UNIVERSAL;
        *outNumber = universalTagOf(type);
        return true;
    }
    *outClass = type->tagClass;
    *outNumber = type->tagNumber;
    return true;
}

bool tagMatches(const asn1::Schema *schema, const asn1::SchemaType *type,
                const asn1::Node *node, bool unwrapped)
{
    if (type->kind == ASN1_TYPE_KIND_ANY) {
        return true;
    }
    if (type->kind == ASN1_TYPE_KIND_CHOICE &&
        (effectiveTagMode(schema, type) != ASN1_TAG_MODE_EXPLICIT ||
         unwrapped)) {
        for (uint32_t i = 0; i < type->fieldCount; ++i) {
            const asn1::SchemaType *branch =
                typeAt(schema, type->fields[i].typeId);
            if (branch != nullptr && tagMatches(schema, branch, node, false)) {
                return true;
            }
        }
        return false;
    }
    uint32_t cls = 0;
    uint32_t num = 0;
    if (!expectedTag(schema, type, unwrapped, &cls, &num)) {
        return false;
    }
    return node->tagClass == cls && node->tagNumber == num;
}

/* 从完整 TLV 计算内容切片；不定长去掉结尾 EOC。 */
bool contentSlice(const uint8_t *tlv, size_t size, const uint8_t **outData,
                  size_t *outSize)
{
    if (tlv == nullptr || size < 2) {
        return false;
    }
    size_t offset = 1;
    if ((tlv[0] & 0x1F) == 0x1F) {
        while (offset < size) {
            const uint8_t byte = tlv[offset++];
            if ((byte & 0x80) == 0) {
                break;
            }
        }
    }
    if (offset >= size) {
        return false;
    }
    const uint8_t lengthByte = tlv[offset++];
    if (lengthByte == 0x80) {
        if (size < offset + 2) {
            return false;
        }
        *outData = tlv + offset;
        *outSize = size - offset - 2;
        return true;
    }
    size_t length = 0;
    if ((lengthByte & 0x80) == 0) {
        length = lengthByte;
    } else {
        const size_t count = lengthByte & 0x7F;
        if (count == 0 || count > 8 || offset + count > size) {
            return false;
        }
        for (size_t i = 0; i < count; ++i) {
            length = (length << 8) | tlv[offset + i];
        }
        offset += count;
    }
    if (length > size - offset) {
        return false;
    }
    *outData = tlv + offset;
    *outSize = length;
    return true;
}

bool integerToDecimal(const uint8_t *data, size_t size, char *out,
                      size_t capacity, bool *outNegative)
{
    if (size == 0 || capacity < 2) {
        return false;
    }
    const bool negative = (data[0] & 0x80) != 0;
    uint8_t magnitude[512];
    if (size > sizeof(magnitude)) {
        return false;
    }
    uint32_t carry = negative ? 1U : 0U;
    for (size_t i = size; i > 0; --i) {
        uint32_t value = static_cast<uint32_t>(data[i - 1]);
        if (negative) {
            value = (~value & 0xFFU) + carry;
            carry = value >> 8;
            value &= 0xFFU;
        }
        magnitude[i - 1] = static_cast<uint8_t>(value);
    }

    char digits[kDecimalDigits];
    size_t count = 1;
    digits[0] = '0';
    for (size_t i = 0; i < size; ++i) {
        uint32_t value = magnitude[i];
        for (size_t d = 0; d < count; ++d) {
            const uint32_t total =
                static_cast<uint32_t>(digits[d] - '0') * 256U + value;
            digits[d] = static_cast<char>('0' + (total % 10U));
            value = total / 10U;
        }
        while (value != 0) {
            if (count >= sizeof(digits)) {
                return false;
            }
            digits[count++] = static_cast<char>('0' + (value % 10U));
            value /= 10U;
        }
    }
    while (count > 1 && digits[count - 1] == '0') {
        --count;
    }
    const size_t total = count + (negative ? 1 : 0);
    if (total + 1 > capacity) {
        return false;
    }
    size_t pos = 0;
    if (negative) {
        out[pos++] = '-';
    }
    for (size_t i = count; i > 0; --i) {
        out[pos++] = digits[i - 1];
    }
    out[pos] = '\0';
    *outNegative = negative;
    return true;
}

/* 比较自身产出的规范十进制文本与 schema 边界文本。 */
bool compareDecimalText(const char *left, size_t leftSize, const char *right,
                        size_t rightSize, int *outOrder)
{
    if (left == nullptr || right == nullptr || outOrder == nullptr) {
        return false;
    }
    size_t li = 0;
    size_t ri = 0;
    const bool lneg = leftSize != 0 && left[0] == '-';
    const bool rneg = rightSize != 0 && right[0] == '-';
    if (lneg) {
        ++li;
    }
    if (rneg) {
        ++ri;
    }
    if (leftSize <= li || rightSize <= ri) {
        return false;
    }
    if (lneg != rneg) {
        *outOrder = lneg ? -1 : 1;
        return true;
    }
    const size_t ldigits = leftSize - li;
    const size_t rdigits = rightSize - ri;
    int order = 0;
    if (ldigits != rdigits) {
        order = ldigits < rdigits ? -1 : 1;
    } else {
        for (size_t i = 0; i < ldigits; ++i) {
            if (left[li + i] != right[ri + i]) {
                order = left[li + i] < right[ri + i] ? -1 : 1;
                break;
            }
        }
    }
    *outOrder = lneg ? -order : order;
    return true;
}

bool parseSmallDecimal(const char *text, int64_t *outValue)
{
    if (text == nullptr || *text == '\0') {
        return false;
    }
    bool negative = false;
    size_t pos = 0;
    if (text[0] == '-') {
        negative = true;
        pos = 1;
    }
    if (text[pos] == '\0') {
        return false;
    }
    int64_t value = 0;
    for (; text[pos] != '\0'; ++pos) {
        if (text[pos] < '0' || text[pos] > '9') {
            return false;
        }
        if (value > (INT64_MAX - 9) / 10) {
            return false;
        }
        value = value * 10 + (text[pos] - '0');
    }
    *outValue = negative ? -value : value;
    return true;
}

bool compareToBound(const char *value, size_t valueSize,
                    const asn1::SchemaBound &bound, int *outOrder)
{
    if (bound.hasDecimal) {
        return compareDecimalText(value, valueSize, bound.decimal,
                                  bound.decimalSize, outOrder);
    }
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "%lld",
                  static_cast<long long>(bound.value));
    return compareDecimalText(value, valueSize, buffer,
                              std::strlen(buffer), outOrder);
}

struct BindContext {
    asn1::Context *ctx;
    asn1::Schema *schema;
    asn1::Document *doc;
    bool strict;
    bool warn;
    bool mutate;
    uint32_t maxDepth;
};

/* 汇总基本节点内容长度（构造字符串按子节点累加）。 */
size_t primitiveLength(const asn1::Node *node)
{
    if (!((node->flags & asn1::kNodeFlagConstructed) != 0)) {
        return node->contentSize;
    }
    size_t total = 0;
    for (const asn1::Node *child = node->firstChild; child != nullptr;
         child = child->nextSibling) {
        total += primitiveLength(child);
    }
    return total;
}

int evalConstraints(BindContext &bind, const asn1::SchemaConstraint *constraints,
                    uint32_t count, const asn1::Node *node,
                    const char *path);

int evalSimpleConstraint(BindContext &bind,
                         const asn1::SchemaConstraint &constraint,
                         const asn1::Node *node, const char *path)
{
    if (constraint.kind == ASN1_CONSTRAINT_SIZE) {
        const size_t length = primitiveLength(node);
        if (!constraint.lowerUnbounded &&
            length < static_cast<size_t>(constraint.lower.value)) {
            asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_CONSTRAINT,
                                          node->tlvOffset, node->depth, path);
            return ASN1_E_SCHEMA_CONSTRAINT;
        }
        if (!constraint.upperUnbounded &&
            length > static_cast<size_t>(constraint.upper.value)) {
            asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_CONSTRAINT,
                                          node->tlvOffset, node->depth, path);
            return ASN1_E_SCHEMA_CONSTRAINT;
        }
        return ASN1_OK;
    }

    /*
     * 数值约束只接受基本编码的数值节点。通用标签下允许 INTEGER 与
     * ENUMERATED；非通用标签（IMPLICIT 覆盖）由类型自身决定语义，
     * 此处只拒绝构造形态。
     */
    const bool constructed =
        (node->flags & asn1::kNodeFlagConstructed) != 0;
    const bool universalNumeric =
        node->tagClass == ASN1_TAG_UNIVERSAL &&
        (node->tagNumber == 2 || node->tagNumber == 10);
    if (constructed ||
        (node->tagClass == ASN1_TAG_UNIVERSAL && !universalNumeric)) {
        asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_CONSTRAINT,
                                      node->tlvOffset, node->depth, path);
        return ASN1_E_SCHEMA_CONSTRAINT;
    }

    char decimal[kDecimalDigits];
    bool negative = false;
    if (!integerToDecimal(node->content, node->contentSize, decimal,
                          sizeof(decimal), &negative)) {
        asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_CONSTRAINT,
                                      node->tlvOffset, node->depth, path);
        return ASN1_E_SCHEMA_CONSTRAINT;
    }
    if (constraint.kind == ASN1_CONSTRAINT_ENUM) {
        int64_t value = 0;
        if (!parseSmallDecimal(decimal, &value)) {
            asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_CONSTRAINT,
                                          node->tlvOffset, node->depth, path);
            return ASN1_E_SCHEMA_CONSTRAINT;
        }
        bool found = false;
        for (uint32_t i = 0; i < constraint.enumCount; ++i) {
            if (constraint.enumValues[i] == value) {
                found = true;
                break;
            }
        }
        if (!found) {
            asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_CONSTRAINT,
                                          node->tlvOffset, node->depth, path);
            return ASN1_E_SCHEMA_CONSTRAINT;
        }
        return ASN1_OK;
    }

    int order = 0;
    if (!constraint.lowerUnbounded) {
        if (!compareToBound(decimal, std::strlen(decimal), constraint.lower,
                            &order)) {
            asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_CONSTRAINT,
                                          node->tlvOffset, node->depth, path);
            return ASN1_E_SCHEMA_CONSTRAINT;
        }
        if (order < 0) {
            asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_CONSTRAINT,
                                          node->tlvOffset, node->depth, path);
            return ASN1_E_SCHEMA_CONSTRAINT;
        }
    }
    if (!constraint.upperUnbounded) {
        if (!compareToBound(decimal, std::strlen(decimal), constraint.upper,
                            &order)) {
            asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_CONSTRAINT,
                                          node->tlvOffset, node->depth, path);
            return ASN1_E_SCHEMA_CONSTRAINT;
        }
        if (order > 0) {
            asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_CONSTRAINT,
                                          node->tlvOffset, node->depth, path);
            return ASN1_E_SCHEMA_CONSTRAINT;
        }
    }
    return ASN1_OK;
}

int evalConstraints(BindContext &bind, const asn1::SchemaConstraint *constraints,
                    uint32_t count, const asn1::Node *node,
                    const char *path)
{
    for (uint32_t i = 0; i < count; ++i) {
        const int rc = evalSimpleConstraint(bind, constraints[i], node, path);
        if (rc != ASN1_OK) {
            return rc;
        }
    }
    return ASN1_OK;
}

int bindType(BindContext &bind, uint32_t typeId, asn1::Node *node,
             const char *fieldName, bool unwrapped, uint32_t depth,
             const char *path);

int bindOf(BindContext &bind, const asn1::SchemaType *type,
           asn1::Node *node, uint32_t depth, const char *path)
{
    const asn1::SchemaType *element = typeAt(bind.schema, type->elementTypeId);
    if (element == nullptr) {
        asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_TYPE,
                                      node->tlvOffset, node->depth, path);
        return ASN1_E_SCHEMA_TYPE;
    }
    uint32_t index = 0;
    for (asn1::Node *child = node->firstChild; child != nullptr;
         child = child->nextSibling) {
        char childPath[kPathBytes];
        std::snprintf(childPath, sizeof(childPath), "%s/[%u]", path,
                      static_cast<unsigned int>(index));
        const int rc = bindType(bind, type->elementTypeId, child, nullptr, false,
                                depth + 1, childPath);
        if (rc != ASN1_OK) {
            return rc;
        }
        ++index;
    }
    if (type->constraintCount != 0) {
        bool sizeOnly = true;
        for (uint32_t i = 0; i < type->constraintCount; ++i) {
            if (type->constraints[i].kind != ASN1_CONSTRAINT_SIZE &&
                type->constraints[i].kind != ASN1_CONSTRAINT_MAX) {
                sizeOnly = false;
            }
        }
        if (sizeOnly) {
            for (uint32_t i = 0; i < type->constraintCount; ++i) {
                const asn1::SchemaConstraint &c = type->constraints[i];
                if (!c.lowerUnbounded &&
                    index < static_cast<size_t>(c.lower.value)) {
                    asn1::contextSetErrorWithPath(
                        bind.ctx, ASN1_E_SCHEMA_CONSTRAINT, node->tlvOffset,
                        node->depth, path);
                    return ASN1_E_SCHEMA_CONSTRAINT;
                }
                if (!c.upperUnbounded &&
                    index > static_cast<size_t>(c.upper.value)) {
                    asn1::contextSetErrorWithPath(
                        bind.ctx, ASN1_E_SCHEMA_CONSTRAINT, node->tlvOffset,
                        node->depth, path);
                    return ASN1_E_SCHEMA_CONSTRAINT;
                }
            }
        } else {
            const int rc = evalConstraints(bind, type->constraints,
                                           type->constraintCount, node, path);
            if (rc != ASN1_OK) {
                return rc;
            }
        }
    }
    return ASN1_OK;
}

int unknownChild(BindContext &bind, const asn1::Node *child, const char *path)
{
    if (bind.strict) {
        asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_FIELD,
                                      child->tlvOffset, child->depth, path);
        return ASN1_E_SCHEMA_FIELD;
    }
    if (bind.warn) {
        asn1::contextAddWarning(bind.ctx, ASN1_E_SCHEMA_FIELD, child->tlvOffset,
                                child->depth, nullptr, "unknown field");
    }
    return ASN1_OK;
}

int bindField(BindContext &bind, const asn1::SchemaField &field,
              asn1::Node *child, uint32_t depth, const char *path)
{
    char childPath[kPathBytes];
    std::snprintf(childPath, sizeof(childPath), "%s/%s", path, field.name);
    if (bind.mutate && child->fieldName == nullptr) {
        const asn1_err_t rc =
            asn1::documentSetFieldName(bind.doc, child, field.name);
        if (rc != ASN1_OK) {
            return rc;
        }
    }
    const int rc = bindType(bind, field.typeId, child, field.name, false,
                            depth + 1, childPath);
    if (rc != ASN1_OK) {
        return rc;
    }
    return evalConstraints(bind, field.constraints, field.constraintCount,
                           child, childPath);
}

int bindSequence(BindContext &bind, const asn1::SchemaType *type,
                 asn1::Node *node, uint32_t depth, const char *path)
{
    uint32_t cursor = 0;
    for (asn1::Node *child = node->firstChild; child != nullptr;
         child = child->nextSibling) {
        size_t match = SIZE_MAX;
        for (uint32_t i = cursor; i < type->fieldCount; ++i) {
            const asn1::SchemaType *fieldType =
                typeAt(bind.schema, type->fields[i].typeId);
            if (fieldType != nullptr && tagMatches(bind.schema, fieldType,
                                                   child, false)) {
                match = i;
                break;
            }
        }
        if (match == SIZE_MAX) {
            const int rc = unknownChild(bind, child, path);
            if (rc != ASN1_OK) {
                return rc;
            }
            continue;
        }
        for (uint32_t i = cursor; i < match; ++i) {
            if ((type->fields[i].flags & ASN1_FIELD_OPTIONAL) == 0 &&
                type->fields[i].defaultSize == 0) {
                asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_FIELD,
                                              child->tlvOffset, child->depth,
                                              path);
                return ASN1_E_SCHEMA_FIELD;
            }
        }
        const int rc = bindField(bind, type->fields[match], child, depth, path);
        if (rc != ASN1_OK) {
            return rc;
        }
        cursor = static_cast<uint32_t>(match) + 1;
    }

    for (uint32_t i = cursor; i < type->fieldCount; ++i) {
        const asn1::SchemaType *fieldType =
            typeAt(bind.schema, type->fields[i].typeId);
        if (fieldType != nullptr &&
            fieldType->kind == ASN1_TYPE_KIND_ANY) {
            if ((type->fields[i].flags & ASN1_FIELD_OPTIONAL) == 0) {
                asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_FIELD,
                                              node->tlvOffset, node->depth,
                                              path);
                return ASN1_E_SCHEMA_FIELD;
            }
            continue;
        }
        if ((type->fields[i].flags & ASN1_FIELD_OPTIONAL) == 0 &&
            type->fields[i].defaultSize == 0) {
            asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_FIELD,
                                          node->tlvOffset, node->depth, path);
            return ASN1_E_SCHEMA_FIELD;
        }
    }
    return ASN1_OK;
}

int bindSet(BindContext &bind, const asn1::SchemaType *type, asn1::Node *node,
            uint32_t depth, const char *path)
{
    for (asn1::Node *child = node->firstChild; child != nullptr;
         child = child->nextSibling) {
        size_t match = SIZE_MAX;
        for (uint32_t i = 0; i < type->fieldCount; ++i) {
            const asn1::SchemaType *fieldType =
                typeAt(bind.schema, type->fields[i].typeId);
            if (fieldType != nullptr && tagMatches(bind.schema, fieldType,
                                                   child, false)) {
                match = i;
                break;
            }
        }
        if (match == SIZE_MAX) {
            const int rc = unknownChild(bind, child, path);
            if (rc != ASN1_OK) {
                return rc;
            }
            continue;
        }
        const int rc = bindField(bind, type->fields[match], child, depth, path);
        if (rc != ASN1_OK) {
            return rc;
        }
    }

    for (uint32_t i = 0; i < type->fieldCount; ++i) {
        if ((type->fields[i].flags & ASN1_FIELD_OPTIONAL) != 0 ||
            type->fields[i].defaultSize != 0) {
            continue;
        }
        bool present = false;
        for (asn1::Node *child = node->firstChild; child != nullptr;
             child = child->nextSibling) {
            const asn1::SchemaType *fieldType =
                typeAt(bind.schema, type->fields[i].typeId);
            if (fieldType != nullptr && tagMatches(bind.schema, fieldType,
                                                   child, false)) {
                present = true;
                break;
            }
        }
        if (!present) {
            asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_FIELD,
                                          node->tlvOffset, node->depth, path);
            return ASN1_E_SCHEMA_FIELD;
        }
    }
    return ASN1_OK;
}

int bindChoice(BindContext &bind, const asn1::SchemaType *type,
               asn1::Node *node, uint32_t depth, const char *path)
{
    for (uint32_t i = 0; i < type->fieldCount; ++i) {
        const asn1::SchemaType *branch =
            typeAt(bind.schema, type->fields[i].typeId);
        if (branch != nullptr && tagMatches(bind.schema, branch, node, false)) {
            return bindField(bind, type->fields[i], node, depth, path);
        }
    }
    asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_TYPE,
                                  node->tlvOffset, node->depth, path);
    return ASN1_E_SCHEMA_TYPE;
}

int markAny(BindContext &bind, const asn1::SchemaType *type, asn1::Node *node,
            uint32_t depth, const char *path)
{
    (void)depth;
    if (!bind.mutate) {
        return ASN1_OK;
    }
    if (node->tlvOffset == SIZE_MAX || node->tlvOffset >= bind.doc->inputSize) {
        asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_TYPE,
                                      node->tlvOffset, node->depth, path);
        return ASN1_E_SCHEMA_TYPE;
    }
    const uint8_t *raw = bind.doc->input + node->tlvOffset;
    if (node->tlvSize > bind.doc->inputSize - node->tlvOffset) {
        asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_TYPE,
                                      node->tlvOffset, node->depth, path);
        return ASN1_E_SCHEMA_TYPE;
    }

    const uint8_t *inner = nullptr;
    size_t innerSize = 0;
    if (effectiveTagMode(bind.schema, type) == ASN1_TAG_MODE_EXPLICIT) {
        if (!((node->flags & asn1::kNodeFlagConstructed) != 0) || node->firstChild == nullptr ||
            node->firstChild->nextSibling != nullptr) {
            asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_TYPE,
                                          node->tlvOffset, node->depth, path);
            return ASN1_E_SCHEMA_TYPE;
        }
        const asn1::Node *child = node->firstChild;
        if (child->tlvOffset == SIZE_MAX ||
            child->tlvSize > bind.doc->inputSize - child->tlvOffset) {
            asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_TYPE,
                                          node->tlvOffset, node->depth, path);
            return ASN1_E_SCHEMA_TYPE;
        }
        inner = bind.doc->input + child->tlvOffset;
        innerSize = child->tlvSize;
    } else {
        const uint8_t *content = nullptr;
        size_t contentSize = 0;
        if (!contentSlice(raw, node->tlvSize, &content, &contentSize)) {
            asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_TYPE,
                                          node->tlvOffset, node->depth, path);
            return ASN1_E_SCHEMA_TYPE;
        }
        inner = content;
        innerSize = contentSize;
    }

    node->flags |= asn1::kNodeFlagAny;
    node->rawTlv = raw;
    node->rawTlvSize = node->tlvSize;
    node->content = inner;
    node->contentSize = innerSize;
    return ASN1_OK;
}

int bindType(BindContext &bind, uint32_t typeId, asn1::Node *node,
             const char *fieldName, bool unwrapped, uint32_t depth,
             const char *path)
{
    const asn1::SchemaType *type = typeAt(bind.schema, typeId);
    if (type == nullptr) {
        asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_TYPE,
                                      node->tlvOffset, node->depth, path);
        return ASN1_E_SCHEMA_TYPE;
    }
    if (depth > bind.maxDepth) {
        asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_DEPTH_LIMIT,
                                      node->tlvOffset, node->depth, path);
        return ASN1_E_DEPTH_LIMIT;
    }
    if (fieldName != nullptr && bind.mutate && node->fieldName == nullptr) {
        const asn1_err_t rc =
            asn1::documentSetFieldName(bind.doc, node, fieldName);
        if (rc != ASN1_OK) {
            return rc;
        }
    }
    (void)fieldName;

    if (type->kind == ASN1_TYPE_KIND_ANY) {
        if (!unwrapped &&
            effectiveTagMode(bind.schema, type) == ASN1_TAG_MODE_EXPLICIT) {
            uint32_t cls = 0;
            uint32_t num = 0;
            if (!expectedTag(bind.schema, type, false, &cls, &num) ||
                node->tagClass != cls || node->tagNumber != num) {
                asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_TYPE,
                                              node->tlvOffset, node->depth,
                                              path);
                return ASN1_E_SCHEMA_TYPE;
            }
        }
        return markAny(bind, type, node, depth, path);
    }

    if (!unwrapped &&
        effectiveTagMode(bind.schema, type) == ASN1_TAG_MODE_EXPLICIT) {
        uint32_t cls = 0;
        uint32_t num = 0;
        if (!expectedTag(bind.schema, type, false, &cls, &num) ||
            node->tagClass != cls || node->tagNumber != num) {
            asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_TYPE,
                                          node->tlvOffset, node->depth, path);
            return ASN1_E_SCHEMA_TYPE;
        }
        if (!((node->flags & asn1::kNodeFlagConstructed) != 0) || node->firstChild == nullptr ||
            node->firstChild->nextSibling != nullptr) {
            asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_TYPE,
                                          node->tlvOffset, node->depth, path);
            return ASN1_E_SCHEMA_TYPE;
        }
        if (type->kind == ASN1_TYPE_KIND_SIMPLE) {
            /* 描述表对 SIMPLE 只记录外层显式标签，内层通用标签不可知，
               因此剥离外层包装后不再校验内层标签，直接评估约束。 */
            return evalConstraints(bind, type->constraints,
                                   type->constraintCount, node->firstChild,
                                   path);
        }
        return bindType(bind, typeId, node->firstChild, nullptr, true,
                        depth, path);
    }

    if (!tagMatches(bind.schema, type, node, unwrapped)) {
        asn1::contextSetErrorWithPath(bind.ctx, ASN1_E_SCHEMA_TYPE,
                                      node->tlvOffset, node->depth, path);
        return ASN1_E_SCHEMA_TYPE;
    }

    switch (type->kind) {
    case ASN1_TYPE_KIND_SEQUENCE:
        return bindSequence(bind, type, node, depth, path);
    case ASN1_TYPE_KIND_SET:
        return bindSet(bind, type, node, depth, path);
    case ASN1_TYPE_KIND_CHOICE:
        return bindChoice(bind, type, node, depth, path);
    case ASN1_TYPE_KIND_SEQUENCE_OF:
    case ASN1_TYPE_KIND_SET_OF:
        return bindOf(bind, type, node, depth, path);
    default:
        return evalConstraints(bind, type->constraints, type->constraintCount,
                               node, path);
    }
}

bool hasKnownFlags(uint32_t flags)
{
    return (flags & ~(ASN1_DECODE_COPY_INPUT | ASN1_DECODE_STRICT_SCHEMA |
                      ASN1_DECODE_WARN_UNKNOWN_FIELD |
                      ASN1_DECODE_ALLOW_TRAILING)) == 0;
}

asn1_err_t prepareOptions(asn1::Context *ctx,
                          const asn1_decode_options_t *options,
                          uint32_t *outMaxDepth, bool *outCopyInput,
                          bool *outAllowTrailing, bool *outStrict, bool *outWarn)
{
    uint32_t maxDepth = ctx->m_maxDepth;
    bool copyInput = false;
    bool allowTrailing = false;
    bool strict = false;
    bool warn = false;
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
        if (!hasKnownFlags(options->flags)) {
            return ASN1_E_INVALID_CONFIG;
        }
        if (options->max_depth != 0) {
            if (options->max_depth > ctx->m_maxDepth) {
                return ASN1_E_INVALID_CONFIG;
            }
            maxDepth = options->max_depth;
        }
        copyInput = (options->flags & ASN1_DECODE_COPY_INPUT) != 0;
        allowTrailing = (options->flags & ASN1_DECODE_ALLOW_TRAILING) != 0;
        strict = (options->flags & ASN1_DECODE_STRICT_SCHEMA) != 0;
        warn = (options->flags & ASN1_DECODE_WARN_UNKNOWN_FIELD) != 0;
    }
    *outMaxDepth = maxDepth;
    *outCopyInput = copyInput;
    *outAllowTrailing = allowTrailing;
    *outStrict = strict;
    *outWarn = strict ? false : warn;
    return ASN1_OK;
}

asn1::Schema *schemaOf(const asn1_schema_t *handle)
{
    if (handle == nullptr) {
        return nullptr;
    }
    return static_cast<asn1::Schema *>(
        const_cast<void *>(static_cast<const void *>(handle)));
}

void reportError(asn1::Context *ctx, asn1_err_t code)
{
    asn1::contextSetError(ctx, code, SIZE_MAX, 0);
}

} /* namespace */

extern "C" asn1_err_t asn1_decode_buffer_with_schema(
    asn1_ctx_t *ctxHandle, const uint8_t *data, size_t size,
    const asn1_schema_t *schemaHandle, const asn1_decode_options_t *options,
    asn1_doc_t **out_doc, size_t *consumed)
{
    if (out_doc == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    *out_doc = nullptr;
    if (ctxHandle == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    asn1::Context *ctx = static_cast<asn1::Context *>(
        static_cast<void *>(ctxHandle));
    if (ctx->m_magic != asn1::kContextMagic || ctx->m_dead) {
        return ASN1_E_INVALID_ARG;
    }
    if (data == nullptr && size != 0) {
        reportError(ctx, ASN1_E_INVALID_ARG);
        return ASN1_E_INVALID_ARG;
    }
    asn1::Schema *schema = schemaOf(schemaHandle);
    if (schema == nullptr || schema->magic != asn1::kSchemaMagic ||
        schema->ctx != ctx) {
        reportError(ctx, ASN1_E_INVALID_ARG);
        return ASN1_E_INVALID_ARG;
    }
    if (!schema->sealed) {
        reportError(ctx, ASN1_E_INVALID_STATE);
        return ASN1_E_INVALID_STATE;
    }
    if (schema->rootTypeId == 0) {
        reportError(ctx, ASN1_E_SCHEMA_TYPE);
        return ASN1_E_SCHEMA_TYPE;
    }

    uint32_t maxDepth = 0;
    bool copyInput = false;
    bool allowTrailing = false;
    bool strict = false;
    bool warn = false;
    const asn1_err_t optionRc =
        prepareOptions(ctx, options, &maxDepth, &copyInput, &allowTrailing,
                       &strict, &warn);
    if (optionRc != ASN1_OK) {
        reportError(ctx, optionRc);
        return optionRc;
    }

    const asn1_encoding_t encoding =
        options == nullptr ? ASN1_ENCODING_BER : options->encoding;

    asn1::contextClearWarnings(ctx);

    asn1::Document *doc = nullptr;
    const asn1_err_t decodeRc =
        asn1::decodeBuffer(ctx, data, size, maxDepth, copyInput, allowTrailing,
                           encoding, &doc, consumed);
    if (decodeRc != ASN1_OK) {
        return decodeRc;
    }

    BindContext bind;
    bind.ctx = ctx;
    bind.schema = schema;
    bind.doc = doc;
    bind.strict = strict;
    bind.warn = warn;
    bind.mutate = true;
    bind.maxDepth = maxDepth;

    const asn1_err_t bindRc =
        bindType(bind, schema->rootTypeId, doc->root, nullptr, false, 0, "");
    if (bindRc != ASN1_OK) {
        asn1::documentDestroy(doc);
        return bindRc;
    }

    *out_doc = reinterpret_cast<asn1_doc_t *>(doc);
    return ASN1_OK;
}

extern "C" asn1_err_t asn1_decode_reader_with_schema(
    asn1_ctx_t *ctxHandle, const asn1_reader_t *reader,
    const asn1_schema_t *schema, const asn1_decode_options_t *options,
    asn1_doc_t **out_doc, size_t *consumed)
{
    if (out_doc == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    *out_doc = nullptr;
    if (ctxHandle == nullptr || reader == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    asn1::Context *ctx = static_cast<asn1::Context *>(
        static_cast<void *>(ctxHandle));
    if (ctx->m_magic != asn1::kContextMagic || ctx->m_dead) {
        return ASN1_E_INVALID_ARG;
    }
    if (reader->read == nullptr ||
        reader->struct_size != sizeof(asn1_reader_t)) {
        reportError(ctx, ASN1_E_INVALID_CONFIG);
        return ASN1_E_INVALID_CONFIG;
    }

    uint8_t *buffer = nullptr;
    size_t used = 0;
    asn1_err_t rc = asn1::readReaderInput(ctx, reader, &buffer, &used);
    if (rc != ASN1_OK) {
        return rc;
    }

    asn1_decode_options_t copyOptions;
    const asn1_decode_options_t *effective = options;
    if (options != nullptr) {
        copyOptions = *options;
        copyOptions.flags |= ASN1_DECODE_COPY_INPUT;
        effective = &copyOptions;
    } else {
        asn1_decode_options_init(&copyOptions);
        copyOptions.flags |= ASN1_DECODE_COPY_INPUT;
        effective = &copyOptions;
    }
    size_t rootEnd = 0;
    rc = asn1_decode_buffer_with_schema(ctxHandle, buffer, used, schema,
                                        effective, out_doc, &rootEnd);
    asn1::contextRelease(ctx, buffer);
    if (rc == ASN1_OK) {
        /* consumed 为实际拉取字节数：允许因预读大于顶层 TLV 长度。 */
        if (consumed != nullptr) {
            *consumed = used;
        }
    }
    return rc;
}

extern "C" asn1_err_t asn1_doc_validate(asn1_ctx_t *ctxHandle,
                                        const asn1_doc_t *docHandle,
                                        const asn1_schema_t *schemaHandle,
                                        const asn1_decode_options_t *options)
{
    if (ctxHandle == nullptr || docHandle == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    asn1::Context *ctx = static_cast<asn1::Context *>(
        static_cast<void *>(ctxHandle));
    if (ctx->m_magic != asn1::kContextMagic || ctx->m_dead) {
        return ASN1_E_INVALID_ARG;
    }
    asn1::Document *doc = static_cast<asn1::Document *>(
        const_cast<void *>(static_cast<const void *>(docHandle)));
    if (doc->magic != asn1::kDocumentMagic || doc->root == nullptr) {
        reportError(ctx, ASN1_E_INVALID_ARG);
        return ASN1_E_INVALID_ARG;
    }
    asn1::Schema *schema = schemaOf(schemaHandle);
    if (schema == nullptr || schema->magic != asn1::kSchemaMagic ||
        schema->ctx != ctx) {
        reportError(ctx, ASN1_E_INVALID_ARG);
        return ASN1_E_INVALID_ARG;
    }
    if (!schema->sealed || schema->rootTypeId == 0) {
        reportError(ctx, ASN1_E_INVALID_STATE);
        return ASN1_E_INVALID_STATE;
    }

    uint32_t maxDepth = 0;
    bool copyInput = false;
    bool allowTrailing = false;
    bool strict = false;
    bool warn = false;
    const asn1_err_t optionRc =
        prepareOptions(ctx, options, &maxDepth, &copyInput, &allowTrailing,
                       &strict, &warn);
    if (optionRc != ASN1_OK) {
        reportError(ctx, optionRc);
        return optionRc;
    }
    (void)copyInput;
    (void)allowTrailing;

    BindContext bind;
    bind.ctx = ctx;
    bind.schema = schema;
    bind.doc = doc;
    bind.strict = strict;
    bind.warn = warn;
    bind.mutate = false;
    bind.maxDepth = maxDepth;

    return bindType(bind, schema->rootTypeId, doc->root, nullptr, false, 0,
                    "");
}
