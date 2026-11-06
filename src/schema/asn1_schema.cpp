/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * schema 运行时注册与封存校验。
 *
 * 职责：创建类型树、追加类型/字段、复制约束与默认值、封存期结构校验。
 * 依赖：core/asn1_context.h、schema/asn1_schema.h。
 * 所有权：所有内容复制进上下文级分配；调用方描述符可立即释放。
 */

#include "asn1_schema.h"

#include <cstring>

namespace asn1 {
namespace {

/* ===== 分配与复制 ===== */

asn1_err_t allocateSchema(Context *ctx, size_t size, void **out) noexcept
{
    return contextAllocate(ctx, size, AllocationKind::kSchema, out);
}

// count * elementSize 是否超出 size_t 可表达范围。
// GCC/Clang 用溢出内建，避免把常量范围比较判成恒假
// （Clang -Wtautological-constant-out-of-range-compare）；其他编译器用除法回退。
bool countOverflowsSize(size_t count, size_t elementSize) noexcept
{
#if defined(__GNUC__) || defined(__clang__)
    size_t total = 0;
    return __builtin_mul_overflow(count, elementSize, &total) != 0;
#else
    return count != 0 && elementSize > SIZE_MAX / count;
#endif
}

void releaseSchema(Context *ctx, void *ptr) noexcept
{
    contextRelease(ctx, ptr);
}

asn1_err_t copyText(Context *ctx, const char *src, const char **out,
                    asn1_err_t invalidCode) noexcept
{
    if (src == nullptr || src[0] == '\0') {
        contextSetError(ctx, invalidCode, SIZE_MAX, 0);
        return invalidCode;
    }
    const size_t len = std::strlen(src);
    char *dst = nullptr;
    void *raw = nullptr;
    const asn1_err_t rc = allocateSchema(ctx, len + 1, &raw);
    if (rc != ASN1_OK) {
        return rc;
    }
    dst = static_cast<char *>(raw);
    std::memcpy(dst, src, len + 1);
    *out = dst;
    return ASN1_OK;
}

asn1_err_t copyBytes(Context *ctx, const void *src, size_t size,
                     const uint8_t **out, asn1_err_t invalidCode) noexcept
{
    if (src == nullptr || size == 0) {
        contextSetError(ctx, invalidCode, SIZE_MAX, 0);
        return invalidCode;
    }
    void *raw = nullptr;
    const asn1_err_t rc = allocateSchema(ctx, size, &raw);
    if (rc != ASN1_OK) {
        return rc;
    }
    std::memcpy(raw, src, size);
    *out = static_cast<const uint8_t *>(raw);
    return ASN1_OK;
}

/* ===== 基础校验 ===== */

bool validKind(uint32_t kind) noexcept
{
    return kind <= static_cast<uint32_t>(ASN1_TYPE_KIND_ANY);
}

bool validTagClass(uint32_t tagClass) noexcept
{
    return tagClass <= static_cast<uint32_t>(ASN1_TAG_PRIVATE);
}

bool validTagMode(uint32_t mode) noexcept
{
    return mode <= static_cast<uint32_t>(ASN1_TAG_MODE_IMPLICIT);
}

bool canonicalUniversalTag(uint32_t kind, uint32_t tagNumber) noexcept
{
    if (kind == static_cast<uint32_t>(ASN1_TYPE_KIND_SEQUENCE) ||
        kind == static_cast<uint32_t>(ASN1_TYPE_KIND_SEQUENCE_OF)) {
        return tagNumber == 0 || tagNumber == 16;
    }
    if (kind == static_cast<uint32_t>(ASN1_TYPE_KIND_SET) ||
        kind == static_cast<uint32_t>(ASN1_TYPE_KIND_SET_OF)) {
        return tagNumber == 0 || tagNumber == 17;
    }
    return false;
}

bool isOfKind(uint32_t kind) noexcept
{
    return kind == static_cast<uint32_t>(ASN1_TYPE_KIND_SEQUENCE_OF) ||
           kind == static_cast<uint32_t>(ASN1_TYPE_KIND_SET_OF);
}

/* docs/02 5.2 与 docs/11 第 4、10 节的类型组合校验。 */
asn1_err_t validateTypeCombination(uint32_t kind, uint32_t tagClass,
                                   uint32_t tagNumber, uint32_t tagMode) noexcept
{
    if (!validKind(kind) || !validTagClass(tagClass) ||
        !validTagMode(tagMode)) {
        return ASN1_E_SCHEMA_TYPE;
    }

    const uint32_t choice = static_cast<uint32_t>(ASN1_TYPE_KIND_CHOICE);
    const uint32_t simple = static_cast<uint32_t>(ASN1_TYPE_KIND_SIMPLE);
    const uint32_t anyKind = static_cast<uint32_t>(ASN1_TYPE_KIND_ANY);
    const uint32_t universal = static_cast<uint32_t>(ASN1_TAG_UNIVERSAL);
    const uint32_t defaultMode = static_cast<uint32_t>(ASN1_TAG_MODE_DEFAULT);
    const uint32_t explicitMode = static_cast<uint32_t>(ASN1_TAG_MODE_EXPLICIT);
    const uint32_t implicitMode = static_cast<uint32_t>(ASN1_TAG_MODE_IMPLICIT);

    if (kind == anyKind) {
        /* ANY 无自身标签：默认形态为 UNIVERSAL 0；或使用非 UNIVERSAL 外层
           EXPLICIT 包装。IMPLICIT 对 ANY 无意义，禁止。 */
        if (tagMode == defaultMode) {
            if (tagClass != universal || tagNumber != 0) {
                return ASN1_E_SCHEMA_TYPE;
            }
            return ASN1_OK;
        }
        if (tagMode == explicitMode) {
            if (tagClass == universal) {
                return ASN1_E_SCHEMA_TYPE;
            }
            return ASN1_OK;
        }
        return ASN1_E_SCHEMA_TYPE;
    }

    if (kind == choice) {
        if (tagMode == implicitMode) {
            return ASN1_E_SCHEMA_TYPE;
        }
        if (tagMode == defaultMode) {
            if (tagClass != universal || tagNumber != 0) {
                return ASN1_E_SCHEMA_TYPE;
            }
        } else if (tagMode == explicitMode) {
            if (tagClass == universal) {
                return ASN1_E_SCHEMA_TYPE;
            }
        }
        return ASN1_OK;
    }

    if (tagClass == universal && tagMode != defaultMode) {
        return ASN1_E_SCHEMA_TYPE;
    }

    if (kind == simple) {
        if (tagClass == universal && tagNumber == 0) {
            return ASN1_E_SCHEMA_TYPE;
        }
        return ASN1_OK;
    }

    if (tagClass == universal && !canonicalUniversalTag(kind, tagNumber)) {
        return ASN1_E_SCHEMA_TYPE;
    }
    return ASN1_OK;
}

bool validDecimalText(const char *text, size_t size) noexcept
{
    if (text == nullptr || size == 0) {
        return false;
    }
    size_t pos = 0;
    bool negative = false;
    if (text[pos] == '-') {
        negative = true;
        ++pos;
        if (pos == size) {
            return false;
        }
    }
    const size_t digits = size - pos;
    if (digits > 1 && text[pos] == '0') {
        return false;
    }
    for (; pos < size; ++pos) {
        if (text[pos] < '0' || text[pos] > '9') {
            return false;
        }
    }
    if (negative && digits == 1 && text[size - 1] == '0') {
        return false; /* "-0" 非法 */
    }
    return true;
}

bool schemaCompareDecimal(const char *left, size_t leftSize,
                          const char *right, size_t rightSize,
                          int *outOrder) noexcept
{
    if (outOrder == nullptr || !validDecimalText(left, leftSize) ||
        !validDecimalText(right, rightSize)) {
        return false;
    }
    bool leftNegative = leftSize > 0 && left[0] == '-';
    bool rightNegative = rightSize > 0 && right[0] == '-';
    size_t leftPos = leftNegative ? 1 : 0;
    size_t rightPos = rightNegative ? 1 : 0;
    size_t leftDigits = leftSize - leftPos;
    size_t rightDigits = rightSize - rightPos;

    int magnitude;
    if (leftDigits != rightDigits) {
        magnitude = leftDigits < rightDigits ? -1 : 1;
    } else {
        magnitude = 0;
        for (size_t i = 0; i < leftDigits; ++i) {
            const char lc = left[leftPos + i];
            const char rc = right[rightPos + i];
            if (lc != rc) {
                magnitude = lc < rc ? -1 : 1;
                break;
            }
        }
    }

    if (leftNegative != rightNegative) {
        *outOrder = leftNegative ? -1 : 1;
    } else if (leftNegative) {
        *outOrder = -magnitude;
    } else {
        *outOrder = magnitude;
    }
    return true;
}

/* 校验公共 bound 描述；返回 ASN1_OK 表示可复制。 */
asn1_err_t validateBoundDesc(Context *ctx, const asn1_bound_t &bound) noexcept
{
    if (bound.struct_size != sizeof(asn1_bound_t) || bound.reserved != 0) {
        contextSetError(ctx, ASN1_E_INVALID_CONFIG, SIZE_MAX, 0);
        return ASN1_E_INVALID_CONFIG;
    }
    if (bound.is_unbounded != 0 && bound.is_unbounded != 1) {
        contextSetError(ctx, ASN1_E_INVALID_CONFIG, SIZE_MAX, 0);
        return ASN1_E_INVALID_CONFIG;
    }
    if (bound.decimal == nullptr && bound.decimal_size != 0) {
        contextSetError(ctx, ASN1_E_INVALID_ARG, SIZE_MAX, 0);
        return ASN1_E_INVALID_ARG;
    }
    if (bound.decimal != nullptr && bound.decimal_size == 0) {
        contextSetError(ctx, ASN1_E_INVALID_ARG, SIZE_MAX, 0);
        return ASN1_E_INVALID_ARG;
    }
    if (bound.decimal != nullptr &&
        !validDecimalText(bound.decimal, bound.decimal_size)) {
        contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
        return ASN1_E_SCHEMA_CONSTRAINT;
    }
    return ASN1_OK;
}

asn1_err_t validateConstraintDesc(Context *ctx,
                                  const asn1_constraint_t &constraint) noexcept
{
    if (constraint.struct_size != sizeof(asn1_constraint_t) ||
        constraint.flags != 0 || constraint.reserved[0] != 0 ||
        constraint.reserved[1] != 0) {
        contextSetError(ctx, ASN1_E_INVALID_CONFIG, SIZE_MAX, 0);
        return ASN1_E_INVALID_CONFIG;
    }
    const uint32_t kind = static_cast<uint32_t>(constraint.kind);
    if (kind > static_cast<uint32_t>(ASN1_CONSTRAINT_BIGINT_RANGE)) {
        contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
        return ASN1_E_SCHEMA_CONSTRAINT;
    }

    if (kind == static_cast<uint32_t>(ASN1_CONSTRAINT_ENUM)) {
        if (constraint.enum_values == nullptr || constraint.enum_count == 0) {
            contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
            return ASN1_E_SCHEMA_CONSTRAINT;
        }
        for (uint32_t i = 0; i < constraint.enum_count; ++i) {
            for (uint32_t j = i + 1; j < constraint.enum_count; ++j) {
                if (constraint.enum_values[i] == constraint.enum_values[j]) {
                    contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
                    return ASN1_E_SCHEMA_CONSTRAINT;
                }
            }
        }
        return ASN1_OK;
    }
    if (constraint.enum_values != nullptr || constraint.enum_count != 0) {
        contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
        return ASN1_E_SCHEMA_CONSTRAINT;
    }

    asn1_err_t rc = validateBoundDesc(ctx, constraint.lower);
    if (rc != ASN1_OK) {
        return rc;
    }
    rc = validateBoundDesc(ctx, constraint.upper);
    if (rc != ASN1_OK) {
        return rc;
    }

    switch (kind) {
    case static_cast<uint32_t>(ASN1_CONSTRAINT_RANGE):
        if (constraint.lower.is_unbounded == 0 &&
            constraint.upper.is_unbounded == 0) {
            if (constraint.lower.decimal != nullptr &&
                constraint.upper.decimal != nullptr) {
                int order = 0;
                if (!schemaCompareDecimal(constraint.lower.decimal,
                                          constraint.lower.decimal_size,
                                          constraint.upper.decimal,
                                          constraint.upper.decimal_size,
                                          &order) ||
                    order > 0) {
                    contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, SIZE_MAX,
                                    0);
                    return ASN1_E_SCHEMA_CONSTRAINT;
                }
            } else if (constraint.lower.value > constraint.upper.value) {
                contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
                return ASN1_E_SCHEMA_CONSTRAINT;
            }
        }
        break;
    case static_cast<uint32_t>(ASN1_CONSTRAINT_SIZE):
        if (constraint.lower.is_unbounded != 0 || constraint.lower.value < 0) {
            contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
            return ASN1_E_SCHEMA_CONSTRAINT;
        }
        if (constraint.upper.is_unbounded == 0 &&
            constraint.upper.value < constraint.lower.value) {
            contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
            return ASN1_E_SCHEMA_CONSTRAINT;
        }
        break;
    case static_cast<uint32_t>(ASN1_CONSTRAINT_MAX):
        if (constraint.upper.is_unbounded != 1 ||
            constraint.lower.is_unbounded != 0 ||
            constraint.lower.value != 0 ||
            constraint.lower.decimal != nullptr ||
            constraint.upper.decimal != nullptr) {
            contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
            return ASN1_E_SCHEMA_CONSTRAINT;
        }
        break;
    case static_cast<uint32_t>(ASN1_CONSTRAINT_BIGINT_RANGE):
        if (constraint.lower.decimal == nullptr &&
            constraint.upper.decimal == nullptr) {
            contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
            return ASN1_E_SCHEMA_CONSTRAINT;
        }
        if (constraint.lower.decimal != nullptr &&
            constraint.upper.decimal != nullptr) {
            int order = 0;
            if (!schemaCompareDecimal(constraint.lower.decimal,
                                      constraint.lower.decimal_size,
                                      constraint.upper.decimal,
                                      constraint.upper.decimal_size,
                                      &order) ||
                order > 0) {
                contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
                return ASN1_E_SCHEMA_CONSTRAINT;
            }
        }
        break;
    default:
        break;
    }
    return ASN1_OK;
}

/* ===== 约束复制 ===== */

void destroyConstraintArray(Context *ctx, SchemaConstraint *constraints,
                            uint32_t count) noexcept
{
    if (constraints == nullptr) {
        return;
    }
    for (uint32_t i = 0; i < count; ++i) {
        releaseSchema(ctx, const_cast<char *>(constraints[i].lower.decimal));
        releaseSchema(ctx, const_cast<char *>(constraints[i].upper.decimal));
        releaseSchema(ctx, const_cast<int64_t *>(constraints[i].enumValues));
    }
    releaseSchema(ctx, constraints);
}

asn1_err_t copyBound(Context *ctx, const asn1_bound_t &src,
                     SchemaBound *dst) noexcept
{
    dst->unbounded = src.is_unbounded != 0;
    dst->hasDecimal = src.decimal != nullptr && src.decimal_size != 0;
    dst->value = src.value;
    dst->decimal = nullptr;
    dst->decimalSize = 0;
    if (dst->hasDecimal) {
        char *copied = nullptr;
        void *raw = nullptr;
        const asn1_err_t rc = allocateSchema(ctx, src.decimal_size, &raw);
        if (rc != ASN1_OK) {
            return rc;
        }
        copied = static_cast<char *>(raw);
        std::memcpy(copied, src.decimal, src.decimal_size);
        dst->decimal = copied;
        dst->decimalSize = src.decimal_size;
    }
    return ASN1_OK;
}

asn1_err_t copyConstraints(Context *ctx, const asn1_constraint_t *src,
                           uint32_t count, SchemaConstraint **out,
                           uint32_t *outCount) noexcept
{
    *out = nullptr;
    *outCount = 0;
    if (count == 0) {
        return ASN1_OK;
    }
    if (src == nullptr ||
        countOverflowsSize(static_cast<size_t>(count),
                           sizeof(SchemaConstraint))) {
        contextSetError(ctx, ASN1_E_INVALID_ARG, SIZE_MAX, 0);
        return ASN1_E_INVALID_ARG;
    }

    SchemaConstraint *array = nullptr;
    void *raw = nullptr;
    asn1_err_t rc = allocateSchema(ctx, count * sizeof(SchemaConstraint), &raw);
    if (rc != ASN1_OK) {
        return rc;
    }
    array = static_cast<SchemaConstraint *>(raw);
    std::memset(array, 0, count * sizeof(SchemaConstraint));

    for (uint32_t i = 0; i < count; ++i) {
        rc = validateConstraintDesc(ctx, src[i]);
        if (rc != ASN1_OK) {
            destroyConstraintArray(ctx, array, i);
            return rc;
        }
        array[i].kind = static_cast<uint32_t>(src[i].kind);
        array[i].lowerUnbounded = src[i].lower.is_unbounded != 0;
        array[i].upperUnbounded = src[i].upper.is_unbounded != 0;

        if (array[i].kind == static_cast<uint32_t>(ASN1_CONSTRAINT_ENUM)) {
            if (countOverflowsSize(static_cast<size_t>(src[i].enum_count),
                                   sizeof(int64_t))) {
                destroyConstraintArray(ctx, array, i);
                contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
                return ASN1_E_SCHEMA_CONSTRAINT;
            }
            void *enumRaw = nullptr;
            rc = allocateSchema(ctx, src[i].enum_count * sizeof(int64_t),
                                &enumRaw);
            if (rc != ASN1_OK) {
                destroyConstraintArray(ctx, array, i);
                return rc;
            }
            int64_t *values = static_cast<int64_t *>(enumRaw);
            std::memcpy(values, src[i].enum_values,
                        src[i].enum_count * sizeof(int64_t));
            array[i].enumValues = values;
            array[i].enumCount = src[i].enum_count;
            continue;
        }

        rc = copyBound(ctx, src[i].lower, &array[i].lower);
        if (rc != ASN1_OK) {
            destroyConstraintArray(ctx, array, i);
            return rc;
        }
        rc = copyBound(ctx, src[i].upper, &array[i].upper);
        if (rc != ASN1_OK) {
            destroyConstraintArray(ctx, array, i);
            return rc;
        }
    }

    *out = array;
    *outCount = count;
    return ASN1_OK;
}

/* 封存期内部约束复检。 */
asn1_err_t validateSchemaConstraint(Context *ctx,
                                    const SchemaConstraint &c) noexcept
{
    const uint32_t kind = c.kind;
    if (kind > static_cast<uint32_t>(ASN1_CONSTRAINT_BIGINT_RANGE)) {
        contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
        return ASN1_E_SCHEMA_CONSTRAINT;
    }
    if (kind == static_cast<uint32_t>(ASN1_CONSTRAINT_ENUM)) {
        if (c.enumValues == nullptr || c.enumCount == 0) {
            contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
            return ASN1_E_SCHEMA_CONSTRAINT;
        }
        for (uint32_t i = 0; i < c.enumCount; ++i) {
            for (uint32_t j = i + 1; j < c.enumCount; ++j) {
                if (c.enumValues[i] == c.enumValues[j]) {
                    contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
                    return ASN1_E_SCHEMA_CONSTRAINT;
                }
            }
        }
        return ASN1_OK;
    }

    const SchemaBound *bounds[2] = {&c.lower, &c.upper};
    for (const SchemaBound *bound : bounds) {
        if (bound->hasDecimal && !validDecimalText(bound->decimal,
                                                   bound->decimalSize)) {
            contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
            return ASN1_E_SCHEMA_CONSTRAINT;
        }
    }

    switch (kind) {
    case static_cast<uint32_t>(ASN1_CONSTRAINT_RANGE):
        if (!c.lower.unbounded && !c.upper.unbounded) {
            if (c.lower.hasDecimal && c.upper.hasDecimal) {
                int order = 0;
                if (!schemaCompareDecimal(c.lower.decimal, c.lower.decimalSize,
                                          c.upper.decimal, c.upper.decimalSize,
                                          &order) ||
                    order > 0) {
                    contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, SIZE_MAX,
                                    0);
                    return ASN1_E_SCHEMA_CONSTRAINT;
                }
            } else if (c.lower.value > c.upper.value) {
                contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
                return ASN1_E_SCHEMA_CONSTRAINT;
            }
        }
        break;
    case static_cast<uint32_t>(ASN1_CONSTRAINT_SIZE):
        if (c.lower.unbounded || c.lower.value < 0) {
            contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
            return ASN1_E_SCHEMA_CONSTRAINT;
        }
        if (!c.upper.unbounded && c.upper.value < c.lower.value) {
            contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
            return ASN1_E_SCHEMA_CONSTRAINT;
        }
        break;
    case static_cast<uint32_t>(ASN1_CONSTRAINT_MAX):
        if (!c.upper.unbounded || c.lower.unbounded || c.lower.value != 0 ||
            c.lower.hasDecimal || c.upper.hasDecimal) {
            contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
            return ASN1_E_SCHEMA_CONSTRAINT;
        }
        break;
    case static_cast<uint32_t>(ASN1_CONSTRAINT_BIGINT_RANGE):
        if (!c.lower.hasDecimal && !c.upper.hasDecimal) {
            contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
            return ASN1_E_SCHEMA_CONSTRAINT;
        }
        if (c.lower.hasDecimal && c.upper.hasDecimal) {
            int order = 0;
            if (!schemaCompareDecimal(c.lower.decimal, c.lower.decimalSize,
                                      c.upper.decimal, c.upper.decimalSize,
                                      &order) ||
                order > 0) {
                contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, SIZE_MAX, 0);
                return ASN1_E_SCHEMA_CONSTRAINT;
            }
        }
        break;
    default:
        break;
    }
    return ASN1_OK;
}

asn1_err_t validateSchemaConstraintArray(Context *ctx,
                                         const SchemaConstraint *array,
                                         uint32_t count) noexcept
{
    for (uint32_t i = 0; i < count; ++i) {
        const asn1_err_t rc = validateSchemaConstraint(ctx, array[i]);
        if (rc != ASN1_OK) {
            return rc;
        }
    }
    return ASN1_OK;
}

/* ===== 类型/字段数组增长 ===== */

asn1_err_t growTypes(Context *ctx, Schema *schema) noexcept
{
    const uint32_t newCapacity =
        schema->typeCapacity == 0 ? 4 : schema->typeCapacity * 2;
    if (newCapacity > UINT32_MAX / 2 ||
        countOverflowsSize(static_cast<size_t>(newCapacity),
                           sizeof(SchemaType))) {
        contextSetError(ctx, ASN1_E_NOMEM, SIZE_MAX, 0);
        return ASN1_E_NOMEM;
    }
    void *raw = nullptr;
    const asn1_err_t rc =
        allocateSchema(ctx, newCapacity * sizeof(SchemaType), &raw);
    if (rc != ASN1_OK) {
        return rc;
    }
    SchemaType *next = static_cast<SchemaType *>(raw);
    std::memset(next, 0, newCapacity * sizeof(SchemaType));
    if (schema->types != nullptr) {
        std::memcpy(next, schema->types,
                    schema->typeCount * sizeof(SchemaType));
        releaseSchema(ctx, schema->types);
    }
    schema->types = next;
    schema->typeCapacity = newCapacity;
    return ASN1_OK;
}

asn1_err_t growFields(Context *ctx, SchemaType *type) noexcept
{
    const uint32_t newCapacity =
        type->fieldCapacity == 0 ? 4 : type->fieldCapacity * 2;
    if (newCapacity > UINT32_MAX / 2 ||
        countOverflowsSize(static_cast<size_t>(newCapacity),
                           sizeof(SchemaField))) {
        contextSetError(ctx, ASN1_E_NOMEM, SIZE_MAX, 0);
        return ASN1_E_NOMEM;
    }
    void *raw = nullptr;
    const asn1_err_t rc =
        allocateSchema(ctx, newCapacity * sizeof(SchemaField), &raw);
    if (rc != ASN1_OK) {
        return rc;
    }
    SchemaField *next = static_cast<SchemaField *>(raw);
    std::memset(next, 0, newCapacity * sizeof(SchemaField));
    if (type->fields != nullptr) {
        std::memcpy(next, type->fields,
                    type->fieldCount * sizeof(SchemaField));
        releaseSchema(ctx, type->fields);
    }
    type->fields = next;
    type->fieldCapacity = newCapacity;
    return ASN1_OK;
}

asn1_err_t growNames(Context *ctx, Schema *schema) noexcept
{
    const uint32_t newCapacity =
        schema->nameCapacity == 0 ? 4 : schema->nameCapacity * 2;
    if (newCapacity > UINT32_MAX / 2 ||
        countOverflowsSize(static_cast<size_t>(newCapacity),
                           sizeof(SchemaName))) {
        contextSetError(ctx, ASN1_E_NOMEM, SIZE_MAX, 0);
        return ASN1_E_NOMEM;
    }
    void *raw = nullptr;
    const asn1_err_t rc =
        allocateSchema(ctx, newCapacity * sizeof(SchemaName), &raw);
    if (rc != ASN1_OK) {
        return rc;
    }
    SchemaName *next = static_cast<SchemaName *>(raw);
    std::memset(next, 0, newCapacity * sizeof(SchemaName));
    if (schema->names != nullptr) {
        std::memcpy(next, schema->names,
                    schema->nameCount * sizeof(SchemaName));
        releaseSchema(ctx, schema->names);
    }
    schema->names = next;
    schema->nameCapacity = newCapacity;
    return ASN1_OK;
}

/* ===== 查找 ===== */

SchemaType *findType(Schema *schema, uint32_t typeId) noexcept
{
    if (typeId == 0 || typeId > schema->typeCount) {
        return nullptr;
    }
    return &schema->types[typeId - 1];
}

const SchemaType *findType(const Schema *schema, uint32_t typeId) noexcept
{
    if (typeId == 0 || typeId > schema->typeCount) {
        return nullptr;
    }
    return &schema->types[typeId - 1];
}

bool typeNameExists(const Schema *schema, const char *name,
                    uint32_t limit) noexcept
{
    for (uint32_t i = 0; i < limit; ++i) {
        if (std::strcmp(schema->types[i].name, name) == 0) {
            return true;
        }
    }
    return false;
}

bool fieldNameExists(const SchemaType *type, const char *name) noexcept
{
    for (uint32_t i = 0; i < type->fieldCount; ++i) {
        if (std::strcmp(type->fields[i].name, name) == 0) {
            return true;
        }
    }
    return false;
}

/* ===== 默认值 DER 校验 ===== */

bool parseTlv(const uint8_t *data, size_t limit, size_t *pos,
              uint32_t depth) noexcept;

bool parseTlvChildren(const uint8_t *data, size_t limit, size_t *pos,
                      uint32_t depth) noexcept
{
    while (*pos < limit) {
        if (!parseTlv(data, limit, pos, depth)) {
            return false;
        }
    }
    return true;
}

bool canonicalPrimitiveValue(uint32_t tagNumber, const uint8_t *content,
                             size_t size, bool constructed) noexcept
{
    switch (tagNumber) {
    case 0: /* EOC 不允许作为默认值内容 */
        return false;
    case 1: /* BOOLEAN */
        return !constructed && size == 1 &&
               (content[0] == 0x00 || content[0] == 0xFF);
    case 2: /* INTEGER */
    case 10: /* ENUMERATED */
        if (constructed || size == 0) {
            return false;
        }
        if (size >= 2) {
            if (content[0] == 0x00 && (content[1] & 0x80) == 0) {
                return false;
            }
            if (content[0] == 0xFF && (content[1] & 0x80) != 0) {
                return false;
            }
        }
        return true;
    case 3: { /* BIT STRING */
        if (constructed || size < 1) {
            return false;
        }
        const uint32_t unused = content[0];
        if (unused > 7) {
            return false;
        }
        if (unused != 0 && size >= 2) {
            const uint8_t mask =
                static_cast<uint8_t>((1u << unused) - 1u);
            if ((content[size - 1] & mask) != 0) {
                return false;
            }
        }
        return true;
    }
    case 4:  /* OCTET STRING */
    case 6:  /* OBJECT IDENTIFIER */
    case 7:  /* ObjectDescriptor */
    case 9:  /* REAL */
    case 12: /* UTF8String */
    case 13: /* RELATIVE-OID */
    case 14: /* TIME */
    case 18: /* NumericString */
    case 19: /* PrintableString */
    case 20: /* TeletexString */
    case 21: /* VideotexString */
    case 22: /* IA5String */
    case 23: /* UTCTime */
    case 24: /* GeneralizedTime */
    case 25: /* GraphicString */
    case 26: /* VisibleString */
    case 27: /* GeneralString */
    case 28: /* UniversalString */
    case 30: /* BMPString */
        return !constructed;
    case 5: /* NULL */
        return !constructed && size == 0;
    case 16: /* SEQUENCE */
    case 17: /* SET */
        return constructed;
    default:
        return true;
    }
}

bool parseTlv(const uint8_t *data, size_t limit, size_t *pos,
              uint32_t depth) noexcept
{
    if (depth > kSchemaMaxTagDepth || *pos >= limit) {
        return false;
    }

    const uint8_t first = data[(*pos)++];
    const uint32_t tagClass = static_cast<uint32_t>(first >> 6);
    const bool constructed = (first & 0x20u) != 0;
    uint32_t tagNumber = static_cast<uint32_t>(first & 0x1Fu);

    if (tagNumber == 0x1Fu) {
        tagNumber = 0;
        bool firstContinuation = true;
        for (;;) {
            if (*pos >= limit) {
                return false;
            }
            const uint8_t b = data[(*pos)++];
            if (firstContinuation && b == 0x80) {
                return false;
            }
            firstContinuation = false;
            if (tagNumber > (UINT32_MAX >> 7)) {
                return false;
            }
            tagNumber = (tagNumber << 7) | static_cast<uint32_t>(b & 0x7Fu);
            if ((b & 0x80u) == 0) {
                break;
            }
        }
        if (tagNumber < 0x1Fu) {
            return false;
        }
    }

    if (*pos >= limit) {
        return false;
    }
    const uint8_t lengthFirst = data[(*pos)++];
    size_t contentSize = 0;
    if (lengthFirst < 0x80u) {
        contentSize = lengthFirst;
    } else {
        const uint32_t count = static_cast<uint32_t>(lengthFirst & 0x7Fu);
        if (count == 0 || count > sizeof(size_t)) {
            return false;
        }
        if (*pos + count > limit) {
            return false;
        }
        if (data[*pos] == 0x00) {
            return false;
        }
        for (uint32_t i = 0; i < count; ++i) {
            contentSize = (contentSize << 8) | data[(*pos)++];
        }
        if (contentSize < 0x80u) {
            return false;
        }
    }

    if (contentSize > limit - *pos) {
        return false;
    }
    const size_t contentStart = *pos;
    const size_t contentEnd = contentStart + contentSize;

    if (constructed) {
        size_t inner = contentStart;
        if (!parseTlvChildren(data, contentEnd, &inner, depth + 1)) {
            return false;
        }
        if (inner != contentEnd) {
            return false;
        }
    }

    if (tagClass == static_cast<uint32_t>(ASN1_TAG_UNIVERSAL) &&
        !canonicalPrimitiveValue(tagNumber, data + contentStart, contentSize,
                                 constructed)) {
        return false;
    }

    *pos = contentEnd;
    return true;
}

/* ===== 标签展开 ===== */

struct EffectiveTag {
    uint32_t tagClass;
    uint32_t tagNumber;
};

struct TagSet {
    EffectiveTag tags[kSchemaMaxTagSet];
    uint32_t count;
};

bool tagSetAdd(TagSet *set, uint32_t tagClass, uint32_t tagNumber) noexcept
{
    for (uint32_t i = 0; i < set->count; ++i) {
        if (set->tags[i].tagClass == tagClass &&
            set->tags[i].tagNumber == tagNumber) {
            return true;
        }
    }
    if (set->count >= kSchemaMaxTagSet) {
        return false;
    }
    set->tags[set->count].tagClass = tagClass;
    set->tags[set->count].tagNumber = tagNumber;
    ++set->count;
    return true;
}

bool tagsIntersect(const TagSet &a, const TagSet &b) noexcept
{
    for (uint32_t i = 0; i < a.count; ++i) {
        for (uint32_t j = 0; j < b.count; ++j) {
            if (a.tags[i].tagClass == b.tags[j].tagClass &&
                a.tags[i].tagNumber == b.tags[j].tagNumber) {
                return true;
            }
        }
    }
    return false;
}

uint32_t defaultUniversalTag(uint32_t kind) noexcept
{
    if (kind == static_cast<uint32_t>(ASN1_TYPE_KIND_SEQUENCE) ||
        kind == static_cast<uint32_t>(ASN1_TYPE_KIND_SEQUENCE_OF)) {
        return 16;
    }
    return 17;
}

bool collectTags(const Schema &schema, uint32_t typeId, uint32_t depth,
                 TagSet *out) noexcept
{
    if (depth > kSchemaMaxTagDepth) {
        return false;
    }
    const SchemaType *type = findType(&schema, typeId);
    if (type == nullptr) {
        return false;
    }
    if (type->kind == static_cast<uint32_t>(ASN1_TYPE_KIND_ANY)) {
        /* 无包装的 ANY 不承诺标签；EXPLICIT ANY 以确定的外层标签参与判定。 */
        if (type->tagMode == static_cast<uint32_t>(ASN1_TAG_MODE_EXPLICIT)) {
            return tagSetAdd(out, type->tagClass, type->tagNumber);
        }
        return false;
    }

    const uint32_t choice = static_cast<uint32_t>(ASN1_TYPE_KIND_CHOICE);
    const uint32_t universal = static_cast<uint32_t>(ASN1_TAG_UNIVERSAL);
    const uint32_t defaultMode = static_cast<uint32_t>(ASN1_TAG_MODE_DEFAULT);
    const uint32_t explicitMode = static_cast<uint32_t>(ASN1_TAG_MODE_EXPLICIT);

    if (type->kind == choice) {
        if (type->tagMode == explicitMode) {
            return tagSetAdd(out, type->tagClass, type->tagNumber);
        }
        if (type->tagMode != defaultMode) {
            return false;
        }
        const uint32_t before = out->count;
        for (uint32_t i = 0; i < type->fieldCount; ++i) {
            if (!collectTags(schema, type->fields[i].typeId, depth + 1, out)) {
                return false;
            }
        }
        /* 分支全部无法给出标签相当于无可判定外层标签。 */
        return out->count > before;
    }

    uint32_t tagNumber = type->tagNumber;
    if (type->tagClass == universal) {
        if (tagNumber == 0) {
            if (type->kind == static_cast<uint32_t>(ASN1_TYPE_KIND_SIMPLE)) {
                return false;
            }
            tagNumber = defaultUniversalTag(type->kind);
        }
    }
    return tagSetAdd(out, type->tagClass, tagNumber);
}

bool validateFieldDefault(Context *ctx, const SchemaField &field) noexcept
{
    if (field.defaultSize != 0 &&
        !schemaValidateDefaultTlv(field.defaultTlv, field.defaultSize)) {
        contextSetError(ctx, ASN1_E_SCHEMA_DEFAULT, SIZE_MAX, 0);
        return false;
    }
    return true;
}

/* ===== 类型追加 ===== */

asn1_err_t appendType(Context *ctx, Schema *schema,
                      const asn1_type_desc_t *desc,
                      bool allowUnregisteredElement,
                      uint32_t *outTypeId) noexcept
{
    asn1_err_t rc = validateTypeCombination(
        static_cast<uint32_t>(desc->kind),
        static_cast<uint32_t>(desc->tag_class), desc->tag_number,
        static_cast<uint32_t>(desc->tag_mode));
    if (rc != ASN1_OK) {
        contextSetError(ctx, rc, SIZE_MAX, 0);
        return rc;
    }
    if ((desc->flags & ~ASN1_TYPE_EXTENSIBLE) != 0) {
        contextSetError(ctx, ASN1_E_INVALID_CONFIG, SIZE_MAX, 0);
        return ASN1_E_INVALID_CONFIG;
    }
    if (desc->constraint_count != 0 && desc->constraints == nullptr) {
        contextSetError(ctx, ASN1_E_INVALID_ARG, SIZE_MAX, 0);
        return ASN1_E_INVALID_ARG;
    }

    if (typeNameExists(schema, desc->name, schema->typeCount)) {
        contextSetError(ctx, ASN1_E_SCHEMA_TYPE, SIZE_MAX, 0);
        return ASN1_E_SCHEMA_TYPE;
    }

    const uint32_t elementId = desc->element_type_id;
    if (isOfKind(static_cast<uint32_t>(desc->kind))) {
        if (elementId == 0 ||
            (!allowUnregisteredElement && elementId > schema->typeCount)) {
            contextSetError(ctx, ASN1_E_SCHEMA_TYPE, SIZE_MAX, 0);
            return ASN1_E_SCHEMA_TYPE;
        }
    } else if (elementId != 0) {
        contextSetError(ctx, ASN1_E_SCHEMA_TYPE, SIZE_MAX, 0);
        return ASN1_E_SCHEMA_TYPE;
    }

    if (static_cast<uint32_t>(desc->kind) ==
            static_cast<uint32_t>(ASN1_TYPE_KIND_ANY) &&
        desc->constraint_count != 0) {
        /* ANY 是开放类型，不得挂约束。 */
        contextSetError(ctx, ASN1_E_SCHEMA_TYPE, SIZE_MAX, 0);
        return ASN1_E_SCHEMA_TYPE;
    }

    SchemaConstraint *constraints = nullptr;
    uint32_t constraintCount = 0;
    rc = copyConstraints(ctx, desc->constraints, desc->constraint_count,
                         &constraints, &constraintCount);
    if (rc != ASN1_OK) {
        return rc;
    }

    const char *name = nullptr;
    rc = copyText(ctx, desc->name, &name, ASN1_E_INVALID_ARG);
    if (rc != ASN1_OK) {
        destroyConstraintArray(ctx, constraints, constraintCount);
        return rc;
    }

    if (schema->typeCount == schema->typeCapacity) {
        rc = growTypes(ctx, schema);
        if (rc != ASN1_OK) {
            releaseSchema(ctx, const_cast<char *>(name));
            destroyConstraintArray(ctx, constraints, constraintCount);
            return rc;
        }
    }

    SchemaType *type = &schema->types[schema->typeCount];
    std::memset(type, 0, sizeof(*type));
    type->name = name;
    type->kind = static_cast<uint32_t>(desc->kind);
    type->tagClass = static_cast<uint32_t>(desc->tag_class);
    type->tagNumber = desc->tag_number;
    type->tagMode = static_cast<uint32_t>(desc->tag_mode);
    type->elementTypeId = elementId;
    type->flags = desc->flags;
    type->constraints = constraints;
    type->constraintCount = constraintCount;

    ++schema->typeCount;
    *outTypeId = schema->typeCount;
    return ASN1_OK;
}

/* ===== 字段追加 ===== */

asn1_err_t appendField(Context *ctx, Schema *schema, uint32_t parentTypeId,
                       const asn1_field_desc_t *desc) noexcept
{
    SchemaType *parent = findType(schema, parentTypeId);
    if (parent == nullptr) {
        contextSetError(ctx, ASN1_E_SCHEMA_TYPE, SIZE_MAX, 0);
        return ASN1_E_SCHEMA_TYPE;
    }
    if (desc->type_id == 0 || desc->type_id > schema->typeCount) {
        contextSetError(ctx, ASN1_E_SCHEMA_TYPE, SIZE_MAX, 0);
        return ASN1_E_SCHEMA_TYPE;
    }
    if ((desc->flags & ~(ASN1_FIELD_OPTIONAL | ASN1_FIELD_EXTENSION)) != 0) {
        contextSetError(ctx, ASN1_E_INVALID_CONFIG, SIZE_MAX, 0);
        return ASN1_E_INVALID_CONFIG;
    }
    if (desc->default_value == nullptr && desc->default_value_size != 0) {
        contextSetError(ctx, ASN1_E_SCHEMA_DEFAULT, SIZE_MAX, 0);
        return ASN1_E_SCHEMA_DEFAULT;
    }
    if (desc->default_value_size != 0 &&
        !schemaValidateDefaultTlv(
            static_cast<const uint8_t *>(desc->default_value),
            desc->default_value_size)) {
        contextSetError(ctx, ASN1_E_SCHEMA_DEFAULT, SIZE_MAX, 0);
        return ASN1_E_SCHEMA_DEFAULT;
    }
    if (desc->field_constraint_count != 0 &&
        desc->field_constraints == nullptr) {
        contextSetError(ctx, ASN1_E_INVALID_ARG, SIZE_MAX, 0);
        return ASN1_E_INVALID_ARG;
    }
    if (parent->kind == static_cast<uint32_t>(ASN1_TYPE_KIND_CHOICE) &&
        (desc->flags != 0 || desc->default_value_size != 0)) {
        contextSetError(ctx, ASN1_E_SCHEMA_FIELD, SIZE_MAX, 0);
        return ASN1_E_SCHEMA_FIELD;
    }
    if (isOfKind(parent->kind)) {
        contextSetError(ctx, ASN1_E_SCHEMA_FIELD, SIZE_MAX, 0);
        return ASN1_E_SCHEMA_FIELD;
    }
    if (parent->kind == static_cast<uint32_t>(ASN1_TYPE_KIND_ANY)) {
        /* ANY 是开放类型，不得挂字段。 */
        contextSetError(ctx, ASN1_E_SCHEMA_FIELD, SIZE_MAX, 0);
        return ASN1_E_SCHEMA_FIELD;
    }
    if (fieldNameExists(parent, desc->name)) {
        contextSetError(ctx, ASN1_E_SCHEMA_FIELD, SIZE_MAX, 0);
        return ASN1_E_SCHEMA_FIELD;
    }

    SchemaConstraint *constraints = nullptr;
    uint32_t constraintCount = 0;
    asn1_err_t rc = copyConstraints(
        ctx, desc->field_constraints, desc->field_constraint_count,
        &constraints, &constraintCount);
    if (rc != ASN1_OK) {
        return rc;
    }

    const char *name = nullptr;
    rc = copyText(ctx, desc->name, &name, ASN1_E_INVALID_ARG);
    if (rc != ASN1_OK) {
        destroyConstraintArray(ctx, constraints, constraintCount);
        return rc;
    }

    const uint8_t *defaultTlv = nullptr;
    if (desc->default_value_size != 0) {
        rc = copyBytes(ctx, desc->default_value, desc->default_value_size,
                       &defaultTlv, ASN1_E_SCHEMA_DEFAULT);
        if (rc != ASN1_OK) {
            releaseSchema(ctx, const_cast<char *>(name));
            destroyConstraintArray(ctx, constraints, constraintCount);
            return rc;
        }
    }

    if (parent->fieldCount == parent->fieldCapacity) {
        rc = growFields(ctx, parent);
        if (rc != ASN1_OK) {
            releaseSchema(ctx, const_cast<char *>(name));
            releaseSchema(ctx, const_cast<uint8_t *>(defaultTlv));
            destroyConstraintArray(ctx, constraints, constraintCount);
            return rc;
        }
    }

    SchemaField *field = &parent->fields[parent->fieldCount];
    std::memset(field, 0, sizeof(*field));
    field->name = name;
    field->typeId = desc->type_id;
    field->flags = desc->flags;
    field->defaultTlv = defaultTlv;
    field->defaultSize = defaultTlv == nullptr ? 0 : desc->default_value_size;
    field->constraints = constraints;
    field->constraintCount = constraintCount;

    ++parent->fieldCount;
    return ASN1_OK;
}

/* ===== 封存校验 ===== */

asn1_err_t sealCheckFields(Context *ctx, Schema *schema) noexcept
{
    for (uint32_t i = 0; i < schema->typeCount; ++i) {
        SchemaType *type = &schema->types[i];
        const bool isChoice =
            type->kind == static_cast<uint32_t>(ASN1_TYPE_KIND_CHOICE);
        const bool isOf = isOfKind(type->kind);
        const bool isAny =
            type->kind == static_cast<uint32_t>(ASN1_TYPE_KIND_ANY);

        if (isAny) {
            if (type->fieldCount != 0) {
                contextSetError(ctx, ASN1_E_SCHEMA_FIELD, SIZE_MAX, 0);
                return ASN1_E_SCHEMA_FIELD;
            }
            if (type->constraintCount != 0) {
                contextSetError(ctx, ASN1_E_SCHEMA_TYPE, SIZE_MAX, 0);
                return ASN1_E_SCHEMA_TYPE;
            }
            continue;
        }

        if (isOf && type->fieldCount != 0) {
            contextSetError(ctx, ASN1_E_SCHEMA_FIELD, SIZE_MAX, 0);
            return ASN1_E_SCHEMA_FIELD;
        }
        for (uint32_t j = 0; j < type->fieldCount; ++j) {
            SchemaField *field = &type->fields[j];
            if (field->typeId == 0 || field->typeId > schema->typeCount) {
                contextSetError(ctx, ASN1_E_SCHEMA_TYPE, SIZE_MAX, 0);
                return ASN1_E_SCHEMA_TYPE;
            }
            if ((field->flags &
                 ~(ASN1_FIELD_OPTIONAL | ASN1_FIELD_EXTENSION)) != 0) {
                contextSetError(ctx, ASN1_E_INVALID_CONFIG, SIZE_MAX, 0);
                return ASN1_E_INVALID_CONFIG;
            }
            if (isChoice &&
                (field->flags != 0 || field->defaultSize != 0)) {
                contextSetError(ctx, ASN1_E_SCHEMA_FIELD, SIZE_MAX, 0);
                return ASN1_E_SCHEMA_FIELD;
            }
            if (!validateFieldDefault(ctx, *field)) {
                return ASN1_E_SCHEMA_DEFAULT;
            }
            const asn1_err_t rc = validateSchemaConstraintArray(
                ctx, field->constraints, field->constraintCount);
            if (rc != ASN1_OK) {
                return rc;
            }
        }
    }
    return ASN1_OK;
}

/* 字段名重复检查（seal 期对每个类型重新确认）。 */
asn1_err_t sealCheckNames(Context *ctx, Schema *schema) noexcept
{
    for (uint32_t i = 0; i < schema->typeCount; ++i) {
        const SchemaType *type = &schema->types[i];
        const asn1_err_t typeRc = validateSchemaConstraintArray(
            ctx, type->constraints, type->constraintCount);
        if (typeRc != ASN1_OK) {
            return typeRc;
        }
        for (uint32_t j = 0; j < type->fieldCount; ++j) {
            for (uint32_t k = j + 1; k < type->fieldCount; ++k) {
                if (std::strcmp(type->fields[j].name,
                                type->fields[k].name) == 0) {
                    contextSetError(ctx, ASN1_E_SCHEMA_FIELD, SIZE_MAX, 0);
                    return ASN1_E_SCHEMA_FIELD;
                }
            }
        }
    }
    return ASN1_OK;
}

asn1_err_t sealCheckTags(Context *ctx, Schema *schema) noexcept
{
    for (uint32_t i = 0; i < schema->typeCount; ++i) {
        const SchemaType *type = &schema->types[i];
        const uint32_t setKind = static_cast<uint32_t>(ASN1_TYPE_KIND_SET);
        const uint32_t choiceKind =
            static_cast<uint32_t>(ASN1_TYPE_KIND_CHOICE);
        const bool isSet = type->kind == setKind;
        const bool isChoice = type->kind == choiceKind;

        if (type->kind == static_cast<uint32_t>(ASN1_TYPE_KIND_SEQUENCE)) {
            for (uint32_t j = 0; j < type->fieldCount; ++j) {
                const SchemaType *fieldType =
                    findType(schema, type->fields[j].typeId);
                const bool isAnyField =
                    fieldType != nullptr &&
                    fieldType->kind == static_cast<uint32_t>(ASN1_TYPE_KIND_ANY);
                const bool unwrappedAny =
                    isAnyField &&
                    fieldType->tagMode ==
                        static_cast<uint32_t>(ASN1_TAG_MODE_DEFAULT);
                if (unwrappedAny) {
                    /* 无包装 ANY 无标签，只能作为末位字段；不参与标签唯一性，
                       也不是后续字段的后继标签。 */
                    if (j + 1 != type->fieldCount) {
                        contextSetError(ctx, ASN1_E_SCHEMA_TYPE, SIZE_MAX, 0);
                        return ASN1_E_SCHEMA_TYPE;
                    }
                    continue;
                }
                if ((type->fields[j].flags & ASN1_FIELD_OPTIONAL) == 0 &&
                    type->fields[j].defaultSize == 0) {
                    continue;
                }
                TagSet first = {};
                if (!collectTags(*schema, type->fields[j].typeId, 0, &first)) {
                    contextSetError(ctx, ASN1_E_SCHEMA_TYPE, SIZE_MAX, 0);
                    return ASN1_E_SCHEMA_TYPE;
                }
                for (uint32_t k = j + 1; k < type->fieldCount; ++k) {
                    const SchemaType *laterType =
                        findType(schema, type->fields[k].typeId);
                    if (laterType != nullptr &&
                        laterType->kind ==
                            static_cast<uint32_t>(ASN1_TYPE_KIND_ANY) &&
                        laterType->tagMode ==
                            static_cast<uint32_t>(ASN1_TAG_MODE_DEFAULT)) {
                        /* 末位无包装 ANY 不提供后继标签。 */
                        continue;
                    }
                    TagSet later = {};
                    if (!collectTags(*schema, type->fields[k].typeId, 0,
                                     &later)) {
                        contextSetError(ctx, ASN1_E_SCHEMA_TYPE, SIZE_MAX, 0);
                        return ASN1_E_SCHEMA_TYPE;
                    }
                    if (tagsIntersect(first, later)) {
                        contextSetError(ctx, ASN1_E_SCHEMA_TYPE, SIZE_MAX, 0);
                        return ASN1_E_SCHEMA_TYPE;
                    }
                }
            }
        }

        if (isSet || isChoice) {
            for (uint32_t j = 0; j < type->fieldCount; ++j) {
                const SchemaType *fieldType =
                    findType(schema, type->fields[j].typeId);
                if (fieldType != nullptr &&
                    fieldType->kind ==
                        static_cast<uint32_t>(ASN1_TYPE_KIND_ANY) &&
                    fieldType->tagMode ==
                        static_cast<uint32_t>(ASN1_TAG_MODE_DEFAULT)) {
                    /* SET/CHOICE 依赖标签识别字段，无包装 ANY 无法判定。 */
                    contextSetError(ctx, ASN1_E_SCHEMA_TYPE, SIZE_MAX, 0);
                    return ASN1_E_SCHEMA_TYPE;
                }
                TagSet first = {};
                if (!collectTags(*schema, type->fields[j].typeId, 0, &first)) {
                    contextSetError(ctx, ASN1_E_SCHEMA_TYPE, SIZE_MAX, 0);
                    return ASN1_E_SCHEMA_TYPE;
                }
                for (uint32_t k = j + 1; k < type->fieldCount; ++k) {
                    TagSet later = {};
                    if (!collectTags(*schema, type->fields[k].typeId, 0,
                                     &later)) {
                        contextSetError(ctx, ASN1_E_SCHEMA_TYPE, SIZE_MAX, 0);
                        return ASN1_E_SCHEMA_TYPE;
                    }
                    if (tagsIntersect(first, later)) {
                        contextSetError(ctx, ASN1_E_SCHEMA_TYPE, SIZE_MAX, 0);
                        return ASN1_E_SCHEMA_TYPE;
                    }
                }
            }
        }
    }
    return ASN1_OK;
}

} /* namespace */

/* ===== 对外内部接口 ===== */

uint32_t schemaCrc32c(const uint8_t *data, size_t size, size_t zeroOffset,
                      size_t zeroLength) noexcept
{
    uint32_t crc = UINT32_C(0xFFFFFFFF);
    for (size_t i = 0; i < size; ++i) {
        const bool zeroed = i >= zeroOffset && i < zeroOffset + zeroLength;
        const uint8_t byte = zeroed ? 0 : data[i];
        crc ^= static_cast<uint32_t>(byte);
        for (uint32_t bit = 0; bit < 8; ++bit) {
            const uint32_t mask =
                static_cast<uint32_t>(0u - (crc & UINT32_C(1)));
            crc = (crc >> 1) ^ (UINT32_C(0x82F63B78) & mask);
        }
    }
    return crc ^ UINT32_C(0xFFFFFFFF);
}

bool schemaValidateDefaultTlv(const uint8_t *data, size_t size) noexcept
{
    if (data == nullptr || size == 0) {
        return false;
    }
    size_t pos = 0;
    if (!parseTlv(data, size, &pos, 0)) {
        return false;
    }
    return pos == size;
}

asn1_err_t schemaCreate(Context *ctx, uint32_t defaultTagMode,
                        Schema **outSchema) noexcept
{
    *outSchema = nullptr;
    if (!validTagMode(defaultTagMode)) {
        contextSetError(ctx, ASN1_E_INVALID_ARG, SIZE_MAX, 0);
        return ASN1_E_INVALID_ARG;
    }

    void *raw = nullptr;
    const asn1_err_t rc =
        allocateSchema(ctx, sizeof(Schema), &raw);
    if (rc != ASN1_OK) {
        return rc;
    }
    Schema *schema = static_cast<Schema *>(raw);
    std::memset(schema, 0, sizeof(*schema));
    schema->ctx = ctx;
    schema->moduleTagMode = defaultTagMode;
    schema->magic = kSchemaMagic;
    *outSchema = schema;
    return ASN1_OK;
}

asn1_err_t schemaAddType(Context *ctx, Schema *schema,
                         const asn1_type_desc_t *desc, uint32_t *outTypeId,
                         bool allowUnregisteredElement) noexcept
{
    *outTypeId = 0;
    if (schema->sealed) {
        contextSetError(ctx, ASN1_E_INVALID_STATE, SIZE_MAX, 0);
        return ASN1_E_INVALID_STATE;
    }
    if (desc->struct_size != sizeof(asn1_type_desc_t) ||
        desc->reserved[0] != 0 || desc->reserved[1] != 0) {
        contextSetError(ctx, ASN1_E_INVALID_CONFIG, SIZE_MAX, 0);
        return ASN1_E_INVALID_CONFIG;
    }
    return appendType(ctx, schema, desc, allowUnregisteredElement, outTypeId);
}

asn1_err_t schemaAddField(Context *ctx, Schema *schema, uint32_t parentTypeId,
                          const asn1_field_desc_t *desc) noexcept
{
    if (schema->sealed) {
        contextSetError(ctx, ASN1_E_INVALID_STATE, SIZE_MAX, 0);
        return ASN1_E_INVALID_STATE;
    }
    if (desc->struct_size != sizeof(asn1_field_desc_t) ||
        desc->reserved[0] != 0 || desc->reserved[1] != 0) {
        contextSetError(ctx, ASN1_E_INVALID_CONFIG, SIZE_MAX, 0);
        return ASN1_E_INVALID_CONFIG;
    }
    return appendField(ctx, schema, parentTypeId, desc);
}

asn1_err_t schemaAddName(Context *ctx, Schema *schema, uint32_t typeId,
                         const char *name, uint32_t kind, uint32_t flags,
                         int64_t value) noexcept
{
    const char *copied = nullptr;
    asn1_err_t rc = copyText(ctx, name, &copied, ASN1_E_SCHEMA_FORMAT);
    if (rc != ASN1_OK) {
        return rc;
    }

    if (schema->nameCount == schema->nameCapacity) {
        rc = growNames(ctx, schema);
        if (rc != ASN1_OK) {
            releaseSchema(ctx, const_cast<char *>(copied));
            return rc;
        }
    }

    SchemaName *entry = &schema->names[schema->nameCount];
    entry->typeId = typeId;
    entry->name = copied;
    entry->kind = kind;
    entry->flags = flags;
    entry->value = value;
    ++schema->nameCount;
    return ASN1_OK;
}

asn1_err_t schemaSetRoot(Context *ctx, Schema *schema,
                         uint32_t rootTypeId) noexcept
{
    if (schema->sealed) {
        contextSetError(ctx, ASN1_E_INVALID_STATE, SIZE_MAX, 0);
        return ASN1_E_INVALID_STATE;
    }
    if (rootTypeId > schema->typeCount) {
        contextSetError(ctx, ASN1_E_SCHEMA_TYPE, SIZE_MAX, 0);
        return ASN1_E_SCHEMA_TYPE;
    }
    schema->rootTypeId = rootTypeId;
    return ASN1_OK;
}

asn1_err_t schemaSeal(Context *ctx, Schema *schema) noexcept
{
    if (schema->sealed) {
        return ASN1_OK;
    }

    if (schema->rootTypeId > schema->typeCount) {
        contextSetError(ctx, ASN1_E_SCHEMA_TYPE, SIZE_MAX, 0);
        return ASN1_E_SCHEMA_TYPE;
    }

    for (uint32_t i = 0; i < schema->typeCount; ++i) {
        SchemaType *type = &schema->types[i];
        asn1_err_t rc = validateTypeCombination(
            type->kind, type->tagClass, type->tagNumber, type->tagMode);
        if (rc != ASN1_OK) {
            contextSetError(ctx, rc, SIZE_MAX, 0);
            return rc;
        }
        if (isOfKind(type->kind)) {
            if (type->elementTypeId == 0 ||
                type->elementTypeId > schema->typeCount) {
                contextSetError(ctx, ASN1_E_SCHEMA_TYPE, SIZE_MAX, 0);
                return ASN1_E_SCHEMA_TYPE;
            }
        } else if (type->elementTypeId != 0) {
            contextSetError(ctx, ASN1_E_SCHEMA_TYPE, SIZE_MAX, 0);
            return ASN1_E_SCHEMA_TYPE;
        }
    }

    asn1_err_t rc = sealCheckFields(ctx, schema);
    if (rc != ASN1_OK) {
        return rc;
    }
    rc = sealCheckNames(ctx, schema);
    if (rc != ASN1_OK) {
        return rc;
    }
    rc = sealCheckTags(ctx, schema);
    if (rc != ASN1_OK) {
        return rc;
    }

    schema->sealed = true;
    return ASN1_OK;
}

void schemaDestroy(Schema *schema) noexcept
{
    if (schema == nullptr || schema->magic != kSchemaMagic) {
        return;
    }
    Context *ctx = schema->ctx;
    for (uint32_t i = 0; i < schema->typeCount; ++i) {
        SchemaType *type = &schema->types[i];
        for (uint32_t j = 0; j < type->fieldCount; ++j) {
            releaseSchema(ctx, const_cast<char *>(type->fields[j].name));
            releaseSchema(ctx,
                          const_cast<uint8_t *>(type->fields[j].defaultTlv));
            destroyConstraintArray(ctx, type->fields[j].constraints,
                                   type->fields[j].constraintCount);
        }
        releaseSchema(ctx, type->fields);
        releaseSchema(ctx, const_cast<char *>(type->name));
        destroyConstraintArray(ctx, type->constraints, type->constraintCount);
    }
    for (uint32_t i = 0; i < schema->nameCount; ++i) {
        releaseSchema(ctx, const_cast<char *>(schema->names[i].name));
    }
    releaseSchema(ctx, schema->names);
    releaseSchema(ctx, schema->types);
    schema->magic = 0;
    releaseSchema(ctx, schema);
}

} /* namespace asn1 */
