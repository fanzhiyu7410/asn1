/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 已编译描述表加载：文件头、CRC32C、五张表与字符串池的显式小端解析。
 *
 * 职责：把 docs/11-描述表格式.md 的字节布局映射到与运行时注册完全相同的
 *       内部类型树，并按第 9 节顺序返回错误码。
 * 依赖：schema/asn1_schema.h、core/asn1_context.h。
 * 所有权：加载产生的名称、约束、默认值全部为上下文级分配；失败时销毁
 *         已创建的 schema，不返回部分类型树。
 */

#include "asn1_schema.h"

#include <cstring>

namespace asn1 {
namespace {

constexpr uint8_t kTableMagic[8] = {0x41, 0x53, 0x4E, 0x31,
                                    0x53, 0x43, 0x48, 0x1A};

constexpr uint32_t kOffFormatVersion = 8;
constexpr uint32_t kOffHeaderSize = 12;
constexpr uint32_t kOffEndianness = 16;
constexpr uint32_t kOffModuleTagMode = 20;
constexpr uint32_t kOffFlags = 24;
constexpr uint32_t kOffChecksumAlg = 28;
constexpr uint32_t kOffTotalSize = 32;
constexpr uint32_t kOffStringPoolOffset = 40;
constexpr uint32_t kOffStringPoolSize = 44;
constexpr uint32_t kOffTypeTableOffset = 48;
constexpr uint32_t kOffTypeCount = 52;
constexpr uint32_t kOffFieldTableOffset = 56;
constexpr uint32_t kOffFieldCount = 60;
constexpr uint32_t kOffConstraintTableOffset = 64;
constexpr uint32_t kOffConstraintCount = 68;
constexpr uint32_t kOffDefaultTableOffset = 72;
constexpr uint32_t kOffDefaultCount = 76;
constexpr uint32_t kOffChecksum = 80;
constexpr uint32_t kOffReserved0 = 84;
constexpr uint32_t kOffReserved1 = 88;
constexpr uint32_t kOffReserved2 = 92;
constexpr uint32_t kOffRootTypeId = 96; /* header_size >= 100 时有效 */
constexpr uint32_t kOffNameTableOffset = 100; /* header_size >= 108 时有效 */
constexpr uint32_t kOffNameCount = 104;       /* header_size >= 108 时有效 */

uint16_t readU16(const uint8_t *data, uint64_t offset) noexcept
{
    return static_cast<uint16_t>(
        static_cast<uint32_t>(data[offset]) |
        (static_cast<uint32_t>(data[offset + 1]) << 8));
}

uint32_t readU32(const uint8_t *data, uint64_t offset) noexcept
{
    return static_cast<uint32_t>(data[offset]) |
           (static_cast<uint32_t>(data[offset + 1]) << 8) |
           (static_cast<uint32_t>(data[offset + 2]) << 16) |
           (static_cast<uint32_t>(data[offset + 3]) << 24);
}

uint64_t readU64(const uint8_t *data, uint64_t offset) noexcept
{
    const uint64_t low = readU32(data, offset);
    const uint64_t high = readU32(data, offset + 4);
    return low | (high << 32);
}

int64_t readI64(const uint8_t *data, uint64_t offset) noexcept
{
    const uint64_t raw = readU64(data, offset);
    if (raw <= static_cast<uint64_t>(INT64_MAX)) {
        return static_cast<int64_t>(raw);
    }
    const uint64_t magnitude = UINT64_MAX - raw;
    return -static_cast<int64_t>(magnitude) - 1;
}

struct TableView {
    const uint8_t *data;
    uint64_t total;
    uint32_t headerSize;
    uint32_t rootTypeId;
    uint32_t stringOffset;
    uint32_t stringSize;
    uint32_t typeOffset;
    uint32_t typeCount;
    uint32_t fieldOffset;
    uint32_t fieldCount;
    uint32_t constraintOffset;
    uint32_t constraintCount;
    uint32_t defaultOffset;
    uint32_t defaultCount;
    uint32_t nameOffset;
    uint32_t nameCount;
};

struct Region {
    uint64_t begin;
    uint64_t end;
};

bool regionsOverlap(const Region &a, const Region &b) noexcept
{
    return a.begin < b.end && b.begin < a.end;
}

bool rangeValid(uint32_t offset, uint32_t count, uint32_t recordSize,
                uint64_t total, Region *out) noexcept
{
    const uint64_t begin = offset;
    const uint64_t bytes = static_cast<uint64_t>(count) * recordSize;
    if (begin > total || bytes > total - begin) {
        return false;
    }
    out->begin = begin;
    out->end = begin + bytes;
    return true;
}

/* 32 位目标上 size_t 窄于 uint64_t：错误详情偏移饱和到 size_t 上限。 */
size_t errorOffset(uint64_t offset) noexcept
{
    return offset > static_cast<uint64_t>(SIZE_MAX) ? SIZE_MAX
                                                    : static_cast<size_t>(offset);
}

asn1_err_t formatError(Context *ctx, uint64_t offset) noexcept
{
    contextSetError(ctx, ASN1_E_SCHEMA_FORMAT, errorOffset(offset), 0);
    return ASN1_E_SCHEMA_FORMAT;
}

/* 类型名/字段名引用的字符串必须非空且在池内 NUL 结尾。 */
bool stringRefValid(const TableView &view, uint32_t offset) noexcept
{
    if (offset == 0 || view.stringSize == 0) {
        return false;
    }
    const uint64_t begin = view.stringOffset;
    const uint64_t end = begin + view.stringSize;
    if (offset <= begin || offset >= end) {
        return false;
    }
    for (uint64_t pos = offset; pos < end; ++pos) {
        if (view.data[pos] == 0) {
            return true;
        }
    }
    return false;
}

/* 十进制文本引用：长度已知，必须整段位于池内且末尾为 NUL。 */
bool decimalRefValid(const TableView &view, uint32_t offset,
                     uint32_t size) noexcept
{
    if (size == 0) {
        return false;
    }
    const uint64_t begin = view.stringOffset;
    const uint64_t end = begin + view.stringSize;
    const uint64_t textBegin = offset;
    const uint64_t textEnd = textBegin + size;
    if (textBegin <= begin || textEnd >= end) {
        return false;
    }
    if (textEnd > view.total) {
        return false;
    }
    return view.data[textEnd] == 0;
}

bool decimalCharsValid(const uint8_t *data, uint32_t offset,
                       uint32_t size) noexcept
{
    if (size == 0) {
        return false;
    }
    const uint64_t end = static_cast<uint64_t>(offset) + size;
    uint64_t pos = offset;
    bool negative = false;
    if (data[pos] == '-') {
        negative = true;
        ++pos;
        if (pos == end) {
            return false;
        }
    }
    const uint64_t digits = end - pos;
    if (digits > 1 && data[pos] == '0') {
        return false;
    }
    for (; pos < end; ++pos) {
        if (data[pos] < '0' || data[pos] > '9') {
            return false;
        }
    }
    if (negative && digits == 1 && data[end - 1] == '0') {
        return false; /* "-0" 非法 */
    }
    return true;
}

/* 比较两个已校验的规范十进制文本，返回 -1/0/1。 */
int compareDecimalText(const uint8_t *data, uint32_t leftOffset,
                       uint32_t leftSize, uint32_t rightOffset,
                       uint32_t rightSize) noexcept
{
    const bool leftNegative = data[leftOffset] == '-';
    const bool rightNegative = data[rightOffset] == '-';
    const uint64_t leftPos = leftNegative ? 1u : 0u;
    const uint64_t rightPos = rightNegative ? 1u : 0u;
    const uint64_t leftDigits = leftSize - leftPos;
    const uint64_t rightDigits = rightSize - rightPos;

    int magnitude = 0;
    if (leftDigits != rightDigits) {
        magnitude = leftDigits < rightDigits ? -1 : 1;
    } else {
        for (uint64_t i = 0; i < leftDigits; ++i) {
            const uint8_t lc = data[leftOffset + leftPos + i];
            const uint8_t rc = data[rightOffset + rightPos + i];
            if (lc != rc) {
                magnitude = lc < rc ? -1 : 1;
                break;
            }
        }
    }

    if (leftNegative != rightNegative) {
        return leftNegative ? -1 : 1;
    }
    return leftNegative ? -magnitude : magnitude;
}

asn1_err_t validateHeader(Context *ctx, const asn1_schema_table_t *table,
                          TableView *view) noexcept
{
    const uint8_t *data = static_cast<const uint8_t *>(table->data);
    const uint64_t total = table->size;

    if (total < kSchemaHeaderSize) {
        return formatError(ctx, kOffHeaderSize);
    }
    for (uint32_t i = 0; i < 8; ++i) {
        if (data[i] != kTableMagic[i]) {
            return formatError(ctx, i);
        }
    }

    const uint32_t formatVersion = readU32(data, kOffFormatVersion);
    const uint32_t major = formatVersion >> 16;
    const uint32_t minor = formatVersion & 0xFFFFu;
    const uint32_t requestedMajor = table->format_version >> 16;
    const uint32_t requestedMinor = table->format_version & 0xFFFFu;
    if (table->format_version != formatVersion ||
        requestedMajor != kSchemaFormatMajor ||
        requestedMinor > kSchemaFormatMinor || major != kSchemaFormatMajor ||
        minor > kSchemaFormatMinor) {
        return formatError(ctx, kOffFormatVersion);
    }

    const uint32_t headerSize = readU32(data, kOffHeaderSize);
    if (headerSize < kSchemaHeaderSize || headerSize > total) {
        return formatError(ctx, kOffHeaderSize);
    }
    if (readU32(data, kOffEndianness) != UINT32_C(0x01020304)) {
        return formatError(ctx, kOffEndianness);
    }
    if (readU32(data, kOffModuleTagMode) > 3) {
        return formatError(ctx, kOffModuleTagMode);
    }
    if (readU32(data, kOffFlags) != 1) {
        return formatError(ctx, kOffFlags);
    }
    if (readU32(data, kOffChecksumAlg) != 1) {
        return formatError(ctx, kOffChecksumAlg);
    }
    if (readU64(data, kOffTotalSize) != total) {
        return formatError(ctx, kOffTotalSize);
    }
    if (readU32(data, kOffReserved0) != 0 ||
        readU32(data, kOffReserved1) != 0 ||
        readU32(data, kOffReserved2) != 0) {
        return formatError(ctx, kOffReserved0);
    }

    /* header_size 低于旧基线 100 时 root_type_id 视作 0（兼容旧基线）。 */
    const uint32_t rootTypeId =
        headerSize >= kSchemaHeaderLegacyBaseSize
            ? readU32(data, kOffRootTypeId)
            : 0;
    /* header_size 低于当前基线 108 时无名称表（offset/count 均为 0）。 */
    const uint32_t nameOffset = headerSize >= kSchemaHeaderBaseSize
                                    ? readU32(data, kOffNameTableOffset)
                                    : 0;
    const uint32_t nameCount = headerSize >= kSchemaHeaderBaseSize
                                   ? readU32(data, kOffNameCount)
                                   : 0;

    const uint32_t stored = readU32(data, kOffChecksum);
    const uint32_t computed =
        schemaCrc32c(data, table->size, kOffChecksum, 4);
    if (stored != computed) {
        return formatError(ctx, kOffChecksum);
    }

    view->data = data;
    view->total = total;
    view->headerSize = headerSize;
    view->rootTypeId = rootTypeId;
    view->stringOffset = readU32(data, kOffStringPoolOffset);
    view->stringSize = readU32(data, kOffStringPoolSize);
    view->typeOffset = readU32(data, kOffTypeTableOffset);
    view->typeCount = readU32(data, kOffTypeCount);
    view->fieldOffset = readU32(data, kOffFieldTableOffset);
    view->fieldCount = readU32(data, kOffFieldCount);
    view->constraintOffset = readU32(data, kOffConstraintTableOffset);
    view->constraintCount = readU32(data, kOffConstraintCount);
    view->defaultOffset = readU32(data, kOffDefaultTableOffset);
    view->defaultCount = readU32(data, kOffDefaultCount);
    view->nameOffset = nameOffset;
    view->nameCount = nameCount;
    return ASN1_OK;
}

asn1_err_t validateRegions(Context *ctx, const TableView &view) noexcept
{
    Region regions[6] = {};
    uint32_t regionCount = 0;

    if (view.stringSize == 0) {
        return formatError(ctx, kOffStringPoolSize);
    }
    if (view.stringOffset < view.headerSize ||
        view.stringOffset > view.total ||
        view.stringSize > view.total - view.stringOffset) {
        return formatError(ctx, kOffStringPoolOffset);
    }
    if (view.data[view.stringOffset] != 0) {
        return formatError(ctx, view.stringOffset);
    }
    regions[regionCount].begin = view.stringOffset;
    regions[regionCount].end =
        static_cast<uint64_t>(view.stringOffset) + view.stringSize;
    ++regionCount;

    Region typeRegion = {};
    Region fieldRegion = {};
    Region constraintRegion = {};
    Region defaultRegion = {};

    if (view.typeCount != 0) {
        if (!rangeValid(view.typeOffset, view.typeCount,
                        kSchemaTypeRecordSize, view.total, &typeRegion) ||
            typeRegion.begin < view.headerSize) {
            return formatError(ctx, kOffTypeTableOffset);
        }
        regions[regionCount++] = typeRegion;
    }
    if (view.fieldCount != 0) {
        if (!rangeValid(view.fieldOffset, view.fieldCount,
                        kSchemaFieldRecordSize, view.total, &fieldRegion) ||
            fieldRegion.begin < view.headerSize) {
            return formatError(ctx, kOffFieldTableOffset);
        }
        regions[regionCount++] = fieldRegion;
    }
    if (view.constraintCount != 0) {
        if (!rangeValid(view.constraintOffset, view.constraintCount,
                        kSchemaConstraintRecordSize, view.total,
                        &constraintRegion) ||
            constraintRegion.begin < view.headerSize) {
            return formatError(ctx, kOffConstraintTableOffset);
        }
        regions[regionCount++] = constraintRegion;
    }
    if (view.defaultCount != 0) {
        if (!rangeValid(view.defaultOffset, view.defaultCount,
                        kSchemaDefaultRecordSize, view.total,
                        &defaultRegion) ||
            defaultRegion.begin < view.headerSize) {
            return formatError(ctx, kOffDefaultTableOffset);
        }
        regions[regionCount++] = defaultRegion;
    }

    Region nameRegion = {};
    if (view.nameCount != 0) {
        if (!rangeValid(view.nameOffset, view.nameCount,
                        kSchemaNameRecordSize, view.total, &nameRegion) ||
            nameRegion.begin < view.headerSize) {
            return formatError(ctx, kOffNameTableOffset);
        }
        regions[regionCount++] = nameRegion;
    }

    for (uint32_t i = 0; i < regionCount; ++i) {
        for (uint32_t j = i + 1; j < regionCount; ++j) {
            if (regionsOverlap(regions[i], regions[j])) {
                return formatError(ctx, regions[j].begin);
            }
        }
    }
    return ASN1_OK;
}

asn1_err_t validateTypeRecords(Context *ctx, const TableView &view) noexcept
{
    for (uint32_t i = 0; i < view.typeCount; ++i) {
        const uint64_t rec =
            static_cast<uint64_t>(view.typeOffset) +
            static_cast<uint64_t>(i) * kSchemaTypeRecordSize;
        if (!stringRefValid(view, readU32(view.data, rec))) {
            return formatError(ctx, rec);
        }
        if (readU16(view.data, rec + 4) > 6) {
            contextSetError(ctx, ASN1_E_SCHEMA_TYPE, errorOffset(rec + 4), 0);
            return ASN1_E_SCHEMA_TYPE;
        }
        if (view.data[rec + 6] > 2) {
            contextSetError(ctx, ASN1_E_SCHEMA_TYPE, errorOffset(rec + 6), 0);
            return ASN1_E_SCHEMA_TYPE;
        }
        if ((view.data[rec + 7] & ~0x01u) != 0 ||
            view.data[rec + 9] != 0 || readU16(view.data, rec + 10) != 0 ||
            readU32(view.data, rec + 36) != 0 ||
            readU32(view.data, rec + 40) != 0 ||
            readU32(view.data, rec + 44) != 0) {
            return formatError(ctx, rec + 7);
        }
        if (view.data[rec + 8] > 3) {
            contextSetError(ctx, ASN1_E_SCHEMA_TYPE, errorOffset(rec + 8), 0);
            return ASN1_E_SCHEMA_TYPE;
        }

        const uint32_t fieldStart = readU32(view.data, rec + 20);
        const uint32_t fieldCount = readU32(view.data, rec + 24);
        if (fieldStart > view.fieldCount ||
            fieldCount > view.fieldCount - fieldStart ||
            fieldCount > view.fieldCount) {
            contextSetError(ctx, ASN1_E_SCHEMA_FIELD, errorOffset(rec + 20), 0);
            return ASN1_E_SCHEMA_FIELD;
        }
        const uint32_t constraintStart = readU32(view.data, rec + 28);
        const uint32_t constraintCount = readU32(view.data, rec + 32);
        if (constraintStart > view.constraintCount ||
            constraintCount > view.constraintCount - constraintStart) {
            contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, errorOffset(rec + 28), 0);
            return ASN1_E_SCHEMA_CONSTRAINT;
        }

        const uint32_t kind = readU16(view.data, rec + 4);
        if ((kind == 4 || kind == 5 || kind == 6) && fieldCount != 0) {
            contextSetError(ctx, ASN1_E_SCHEMA_FIELD, errorOffset(rec + 20), 0);
            return ASN1_E_SCHEMA_FIELD;
        }
    }

    for (uint32_t i = 0; i < view.typeCount; ++i) {
        const uint64_t recA =
            static_cast<uint64_t>(view.typeOffset) +
            static_cast<uint64_t>(i) * kSchemaTypeRecordSize;
        const uint32_t startA = readU32(view.data, recA + 20);
        const uint32_t countA = readU32(view.data, recA + 24);
        if (countA == 0) {
            continue;
        }
        const Region regionA = {startA, static_cast<uint64_t>(startA) + countA};
        for (uint32_t j = i + 1; j < view.typeCount; ++j) {
            const uint64_t recB =
                static_cast<uint64_t>(view.typeOffset) +
                static_cast<uint64_t>(j) * kSchemaTypeRecordSize;
            const uint32_t startB = readU32(view.data, recB + 20);
            const uint32_t countB = readU32(view.data, recB + 24);
            if (countB == 0) {
                continue;
            }
            const Region regionB = {
                startB, static_cast<uint64_t>(startB) + countB};
            if (regionsOverlap(regionA, regionB)) {
                contextSetError(ctx, ASN1_E_SCHEMA_FIELD, errorOffset(recB + 20), 0);
                return ASN1_E_SCHEMA_FIELD;
            }
        }
    }

    if (view.rootTypeId != 0 && view.rootTypeId > view.typeCount) {
        return formatError(ctx, kOffRootTypeId);
    }
    return ASN1_OK;
}

asn1_err_t validateFieldRecords(Context *ctx, const TableView &view) noexcept
{
    for (uint32_t i = 0; i < view.fieldCount; ++i) {
        const uint64_t rec =
            static_cast<uint64_t>(view.fieldOffset) +
            static_cast<uint64_t>(i) * kSchemaFieldRecordSize;
        if (!stringRefValid(view, readU32(view.data, rec))) {
            return formatError(ctx, rec);
        }
        const uint32_t typeId = readU32(view.data, rec + 4);
        if (typeId == 0 || typeId > view.typeCount) {
            contextSetError(ctx, ASN1_E_SCHEMA_TYPE, errorOffset(rec + 4), 0);
            return ASN1_E_SCHEMA_TYPE;
        }
        if ((readU16(view.data, rec + 8) & ~0x0003u) != 0 ||
            readU16(view.data, rec + 10) != 0 ||
            readU32(view.data, rec + 24) != 0 ||
            readU32(view.data, rec + 28) != 0) {
            return formatError(ctx, rec + 8);
        }
        const uint32_t defaultIndex = readU32(view.data, rec + 12);
        if (defaultIndex > view.defaultCount) {
            contextSetError(ctx, ASN1_E_SCHEMA_DEFAULT, errorOffset(rec + 12), 0);
            return ASN1_E_SCHEMA_DEFAULT;
        }
        const uint32_t constraintStart = readU32(view.data, rec + 16);
        const uint32_t constraintCount = readU32(view.data, rec + 20);
        if (constraintStart > view.constraintCount ||
            constraintCount > view.constraintCount - constraintStart) {
            contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, errorOffset(rec + 16), 0);
            return ASN1_E_SCHEMA_CONSTRAINT;
        }
    }
    return ASN1_OK;
}

asn1_err_t validateConstraintRecords(Context *ctx,
                                     const TableView &view) noexcept
{
    for (uint32_t i = 0; i < view.constraintCount; ++i) {
        const uint64_t rec =
            static_cast<uint64_t>(view.constraintOffset) +
            static_cast<uint64_t>(i) * kSchemaConstraintRecordSize;
        const uint32_t kind = readU16(view.data, rec);
        if (kind > 4) {
            return formatError(ctx, rec);
        }
        const uint16_t flags = readU16(view.data, rec + 2);
        if ((flags & ~0x0003u) != 0 || readU32(view.data, rec + 44) != 0) {
            return formatError(ctx, rec + 2);
        }
        const bool lowerUnbounded = (flags & 0x0001u) != 0;
        const bool upperUnbounded = (flags & 0x0002u) != 0;

        const uint32_t enumOff = readU32(view.data, rec + 4);
        const uint32_t enumCount = readU32(view.data, rec + 8);
        if (kind == 2) {
            if (enumCount == 0) {
                return formatError(ctx, rec + 8);
            }
            if ((enumOff & 7u) != 0 || enumOff > view.total ||
                static_cast<uint64_t>(enumCount) * sizeof(int64_t) >
                    view.total - enumOff) {
                contextSetError(ctx, ASN1_E_SCHEMA_CONSTRAINT, errorOffset(rec + 4), 0);
                return ASN1_E_SCHEMA_CONSTRAINT;
            }
            for (uint32_t a = 0; a < enumCount; ++a) {
                const int64_t valueA = readI64(
                    view.data, static_cast<uint64_t>(enumOff) +
                                   static_cast<uint64_t>(a) * 8);
                for (uint32_t b = a + 1; b < enumCount; ++b) {
                    const int64_t valueB = readI64(
                        view.data, static_cast<uint64_t>(enumOff) +
                                       static_cast<uint64_t>(b) * 8);
                    if (valueA == valueB) {
                        return formatError(ctx, rec + 4);
                    }
                }
            }
        } else if (enumOff != 0 || enumCount != 0) {
            return formatError(ctx, rec + 4);
        }

        const uint32_t lowerOff = readU32(view.data, rec + 12);
        const uint32_t lowerSize = readU32(view.data, rec + 16);
        const uint32_t upperOff = readU32(view.data, rec + 20);
        const uint32_t upperSize = readU32(view.data, rec + 24);
        if ((lowerOff != 0 || lowerSize != 0) &&
            !decimalRefValid(view, lowerOff, lowerSize)) {
            return formatError(ctx, rec + 12);
        }
        if ((upperOff != 0 || upperSize != 0) &&
            !decimalRefValid(view, upperOff, upperSize)) {
            return formatError(ctx, rec + 20);
        }
        if (lowerOff != 0 &&
            !decimalCharsValid(view.data, lowerOff, lowerSize)) {
            return formatError(ctx, rec + 12);
        }
        if (upperOff != 0 &&
            !decimalCharsValid(view.data, upperOff, upperSize)) {
            return formatError(ctx, rec + 20);
        }

        const int64_t lowerValue = readI64(view.data, rec + 28);
        const int64_t upperValue = readI64(view.data, rec + 36);

        switch (kind) {
        case 0: /* RANGE */
            if (!lowerUnbounded && !upperUnbounded) {
                if (lowerOff != 0 && upperOff != 0) {
                    if (compareDecimalText(view.data, lowerOff, lowerSize,
                                           upperOff, upperSize) > 0) {
                        return formatError(ctx, rec + 12);
                    }
                } else if (lowerValue > upperValue) {
                    return formatError(ctx, rec + 28);
                }
            }
            break;
        case 1: /* SIZE */
            if (lowerUnbounded || lowerValue < 0) {
                return formatError(ctx, rec + 28);
            }
            if (!upperUnbounded && upperValue < lowerValue) {
                return formatError(ctx, rec + 36);
            }
            break;
        case 3: /* MAX：上界无界，下界固定为 0 且不得给出 lower */
            if (!upperUnbounded || lowerUnbounded || lowerValue != 0 ||
                lowerOff != 0 || upperOff != 0) {
                return formatError(ctx, rec + 2);
            }
            break;
        case 4: /* BIGINT_RANGE */
            if (lowerOff == 0 && upperOff == 0) {
                return formatError(ctx, rec + 12);
            }
            if (lowerOff != 0 && upperOff != 0 &&
                compareDecimalText(view.data, lowerOff, lowerSize, upperOff,
                                   upperSize) > 0) {
                return formatError(ctx, rec + 12);
            }
            break;
        default:
            break;
        }
    }
    return ASN1_OK;
}

asn1_err_t validateDefaultRecords(Context *ctx, const TableView &view) noexcept
{
    Region occupied[8] = {};
    uint32_t occupiedCount = 0;
    occupied[occupiedCount++] = {0, view.headerSize};
    occupied[occupiedCount++] = {
        view.stringOffset,
        static_cast<uint64_t>(view.stringOffset) + view.stringSize};

    if (view.typeCount != 0) {
        occupied[occupiedCount++] = {
            view.typeOffset, static_cast<uint64_t>(view.typeOffset) +
                                 static_cast<uint64_t>(view.typeCount) *
                                     kSchemaTypeRecordSize};
    }
    if (view.fieldCount != 0) {
        occupied[occupiedCount++] = {
            view.fieldOffset, static_cast<uint64_t>(view.fieldOffset) +
                                  static_cast<uint64_t>(view.fieldCount) *
                                      kSchemaFieldRecordSize};
    }
    if (view.constraintCount != 0) {
        occupied[occupiedCount++] = {
            view.constraintOffset,
            static_cast<uint64_t>(view.constraintOffset) +
                static_cast<uint64_t>(view.constraintCount) *
                    kSchemaConstraintRecordSize};
    }
    if (view.defaultCount != 0) {
        occupied[occupiedCount++] = {
            view.defaultOffset,
            static_cast<uint64_t>(view.defaultOffset) +
                static_cast<uint64_t>(view.defaultCount) *
                    kSchemaDefaultRecordSize};
    }
    if (view.nameCount != 0) {
        occupied[occupiedCount++] = {
            view.nameOffset, static_cast<uint64_t>(view.nameOffset) +
                                 static_cast<uint64_t>(view.nameCount) *
                                     kSchemaNameRecordSize};
    }

    for (uint32_t i = 0; i < view.defaultCount; ++i) {
        const uint64_t rec =
            static_cast<uint64_t>(view.defaultOffset) +
            static_cast<uint64_t>(i) * kSchemaDefaultRecordSize;
        const uint32_t dataOffset = readU32(view.data, rec);
        const uint32_t dataSize = readU32(view.data, rec + 4);
        if (dataSize == 0 || dataOffset < view.headerSize ||
            dataOffset > view.total ||
            dataSize > view.total - dataOffset) {
            contextSetError(ctx, ASN1_E_SCHEMA_DEFAULT, errorOffset(rec), 0);
            return ASN1_E_SCHEMA_DEFAULT;
        }
        const Region region = {
            dataOffset, static_cast<uint64_t>(dataOffset) + dataSize};
        for (uint32_t j = 0; j < occupiedCount; ++j) {
            if (regionsOverlap(region, occupied[j])) {
                contextSetError(ctx, ASN1_E_SCHEMA_DEFAULT, errorOffset(rec), 0);
                return ASN1_E_SCHEMA_DEFAULT;
            }
        }
        if (!schemaValidateDefaultTlv(view.data + dataOffset, dataSize)) {
            contextSetError(ctx, ASN1_E_SCHEMA_DEFAULT, errorOffset(rec), 0);
            return ASN1_E_SCHEMA_DEFAULT;
        }
    }
    return ASN1_OK;
}

/* 类型或引用该类型的字段上是否存在有限上界的 SIZE 约束；返回最小上界。 */
bool finiteSizeUpperBound(const TableView &view, uint32_t typeId,
                          int64_t *outUpper) noexcept
{
    const uint64_t typeRec =
        static_cast<uint64_t>(view.typeOffset) +
        static_cast<uint64_t>(typeId - 1) * kSchemaTypeRecordSize;

    bool found = false;
    int64_t best = 0;
    auto consider = [&](uint32_t start, uint32_t count) noexcept {
        for (uint32_t i = 0; i < count; ++i) {
            const uint64_t rec =
                static_cast<uint64_t>(view.constraintOffset) +
                static_cast<uint64_t>(start + i) * kSchemaConstraintRecordSize;
            if (readU16(view.data, rec) != 1) {
                continue; /* 仅 SIZE */
            }
            if ((readU16(view.data, rec + 2) & 0x0002u) != 0) {
                continue; /* 上界无界 */
            }
            const int64_t upper = readI64(view.data, rec + 36);
            if (!found || upper < best) {
                best = upper;
                found = true;
            }
        }
    };

    consider(readU32(view.data, typeRec + 28), readU32(view.data, typeRec + 32));

    for (uint32_t i = 0; i < view.fieldCount; ++i) {
        const uint64_t fieldRec =
            static_cast<uint64_t>(view.fieldOffset) +
            static_cast<uint64_t>(i) * kSchemaFieldRecordSize;
        if (readU32(view.data, fieldRec + 4) != typeId) {
            continue;
        }
        consider(readU32(view.data, fieldRec + 16),
                 readU32(view.data, fieldRec + 20));
    }

    if (found) {
        *outUpper = best;
    }
    return found;
}

asn1_err_t validateNameRecords(Context *ctx, const TableView &view) noexcept
{
    const uint32_t simpleKind = static_cast<uint32_t>(ASN1_TYPE_KIND_SIMPLE);
    const uint32_t universal = static_cast<uint32_t>(ASN1_TAG_UNIVERSAL);

    for (uint32_t i = 0; i < view.nameCount; ++i) {
        const uint64_t rec =
            static_cast<uint64_t>(view.nameOffset) +
            static_cast<uint64_t>(i) * kSchemaNameRecordSize;
        const uint32_t typeId = readU32(view.data, rec);
        if (typeId == 0 || typeId > view.typeCount) {
            return formatError(ctx, rec);
        }
        const uint32_t nameOff = readU32(view.data, rec + 4);
        if (!stringRefValid(view, nameOff)) {
            return formatError(ctx, rec + 4);
        }
        const uint32_t kind = readU16(view.data, rec + 8);
        if (kind > 1) {
            return formatError(ctx, rec + 8);
        }
        const uint16_t flags = readU16(view.data, rec + 10);
        if ((flags & ~0x0001u) != 0) {
            return formatError(ctx, rec + 10);
        }
        if (readU32(view.data, rec + 12) != 0) {
            return formatError(ctx, rec + 12);
        }
        const int64_t value = readI64(view.data, rec + 16);

        const uint64_t typeRec =
            static_cast<uint64_t>(view.typeOffset) +
            static_cast<uint64_t>(typeId - 1) * kSchemaTypeRecordSize;
        const uint32_t typeKind = readU16(view.data, typeRec + 4);
        const uint32_t tagClass = view.data[typeRec + 8];
        const uint32_t tagNumber = readU32(view.data, typeRec + 12);
        const uint32_t typeFlags = view.data[typeRec + 7];

        if (kind == 0) { /* BIT_NAME */
            if (flags != 0) {
                return formatError(ctx, rec + 10);
            }
            if (typeKind != simpleKind || tagClass != universal ||
                tagNumber != 3) {
                return formatError(ctx, rec);
            }
            if (value < 0 || value > 65535) {
                return formatError(ctx, rec + 16);
            }
            int64_t upper = 0;
            if (finiteSizeUpperBound(view, typeId, &upper) && value >= upper) {
                return formatError(ctx, rec + 16);
            }
        } else { /* NUMBER_NAME */
            if (typeKind != simpleKind || tagClass != universal ||
                (tagNumber != 10 && tagNumber != 2)) {
                return formatError(ctx, rec);
            }
            if ((flags & 0x0001u) != 0 &&
                (typeFlags & ASN1_TYPE_EXTENSIBLE) == 0) {
                return formatError(ctx, rec + 10);
            }
        }

        for (uint32_t j = 0; j < i; ++j) {
            const uint64_t prev =
                static_cast<uint64_t>(view.nameOffset) +
                static_cast<uint64_t>(j) * kSchemaNameRecordSize;
            if (readU32(view.data, prev) != typeId) {
                continue;
            }
            const uint32_t prevOff = readU32(view.data, prev + 4);
            const uint32_t prevKind = readU16(view.data, prev + 8);
            if (std::strcmp(
                    reinterpret_cast<const char *>(view.data + nameOff),
                    reinterpret_cast<const char *>(view.data + prevOff)) == 0) {
                return formatError(ctx, rec + 4);
            }
            if (prevKind != kind) {
                return formatError(ctx, rec + 8);
            }
            if (readI64(view.data, prev + 16) == value) {
                return formatError(ctx, rec + 16);
            }
        }
    }
    return ASN1_OK;
}

/* ===== 记录到描述符的转换 ===== */

struct ConstraintPack {
    asn1_constraint_t *descs;
    uint32_t count;
    int64_t **enums;
};

void freeConstraintPack(Context *ctx, ConstraintPack *pack) noexcept
{
    if (pack->enums != nullptr) {
        for (uint32_t i = 0; i < pack->count; ++i) {
            contextRelease(ctx, pack->enums[i]);
        }
        contextRelease(ctx, pack->enums);
    }
    contextRelease(ctx, pack->descs);
    pack->descs = nullptr;
    pack->enums = nullptr;
    pack->count = 0;
}

asn1_err_t packConstraints(Context *ctx, const TableView &view,
                           uint32_t start, uint32_t count,
                           ConstraintPack *pack) noexcept
{
    pack->descs = nullptr;
    pack->enums = nullptr;
    pack->count = 0;
    if (count == 0) {
        return ASN1_OK;
    }

    void *descRaw = nullptr;
    asn1_err_t rc = contextAllocate(
        ctx, static_cast<size_t>(count) * sizeof(asn1_constraint_t),
        AllocationKind::kSchema, &descRaw);
    if (rc != ASN1_OK) {
        return rc;
    }
    pack->descs = static_cast<asn1_constraint_t *>(descRaw);
    std::memset(pack->descs, 0, static_cast<size_t>(count) *
                                  sizeof(asn1_constraint_t));
    pack->count = count;

    void *enumRaw = nullptr;
    rc = contextAllocate(ctx, static_cast<size_t>(count) * sizeof(int64_t *),
                         AllocationKind::kSchema, &enumRaw);
    if (rc != ASN1_OK) {
        freeConstraintPack(ctx, pack);
        return rc;
    }
    pack->enums = static_cast<int64_t **>(enumRaw);
    std::memset(pack->enums, 0,
                static_cast<size_t>(count) * sizeof(int64_t *));

    for (uint32_t i = 0; i < count; ++i) {
        const uint64_t rec =
            static_cast<uint64_t>(view.constraintOffset) +
            static_cast<uint64_t>(start + i) * kSchemaConstraintRecordSize;
        asn1_constraint_t *desc = &pack->descs[i];
        desc->struct_size = sizeof(asn1_constraint_t);
        desc->kind =
            static_cast<asn1_constraint_kind_t>(readU16(view.data, rec));
        desc->flags = 0;
        const uint16_t flags = readU16(view.data, rec + 2);
        desc->lower.struct_size = sizeof(asn1_bound_t);
        desc->lower.is_unbounded =
            static_cast<int32_t>(flags & 0x0001u);
        desc->lower.value = readI64(view.data, rec + 28);
        desc->upper.struct_size = sizeof(asn1_bound_t);
        desc->upper.is_unbounded =
            static_cast<int32_t>((flags >> 1) & 0x0001u);
        desc->upper.value = readI64(view.data, rec + 36);

        if (desc->kind == ASN1_CONSTRAINT_ENUM) {
            const uint32_t enumOff = readU32(view.data, rec + 4);
            const uint32_t enumCount = readU32(view.data, rec + 8);
            void *valuesRaw = nullptr;
            rc = contextAllocate(ctx,
                                 static_cast<size_t>(enumCount) *
                                     sizeof(int64_t),
                                 AllocationKind::kSchema, &valuesRaw);
            if (rc != ASN1_OK) {
                freeConstraintPack(ctx, pack);
                return rc;
            }
            int64_t *values = static_cast<int64_t *>(valuesRaw);
            for (uint32_t j = 0; j < enumCount; ++j) {
                values[j] = readI64(view.data,
                                    static_cast<uint64_t>(enumOff) +
                                        static_cast<uint64_t>(j) * 8);
            }
            pack->enums[i] = values;
            desc->enum_values = values;
            desc->enum_count = enumCount;
        } else {
            const uint32_t lowerOff = readU32(view.data, rec + 12);
            const uint32_t lowerSize = readU32(view.data, rec + 16);
            const uint32_t upperOff = readU32(view.data, rec + 20);
            const uint32_t upperSize = readU32(view.data, rec + 24);
            if (lowerOff != 0) {
                desc->lower.decimal =
                    reinterpret_cast<const char *>(view.data + lowerOff);
                desc->lower.decimal_size = lowerSize;
            }
            if (upperOff != 0) {
                desc->upper.decimal =
                    reinterpret_cast<const char *>(view.data + upperOff);
                desc->upper.decimal_size = upperSize;
            }
        }
    }
    return ASN1_OK;
}

/* docs/11 第 2 节：0=AUTOMATIC、2=IMPLICIT 均归一为 IMPLICIT；
 * 1=EXPLICIT；3=未声明归一为 DEFAULT。 */
uint32_t normalizedModuleTagMode(uint32_t headerMode) noexcept
{
    switch (headerMode) {
    case 0:
    case 2:
        return static_cast<uint32_t>(ASN1_TAG_MODE_IMPLICIT);
    case 1:
        return static_cast<uint32_t>(ASN1_TAG_MODE_EXPLICIT);
    default:
        return static_cast<uint32_t>(ASN1_TAG_MODE_DEFAULT);
    }
}

asn1_err_t buildTree(Context *ctx, const TableView &view,
                     Schema **outSchema) noexcept
{
    const uint32_t headerMode = readU32(view.data, kOffModuleTagMode);
    Schema *schema = nullptr;
    asn1_err_t rc =
        schemaCreate(ctx, normalizedModuleTagMode(headerMode), &schema);
    if (rc != ASN1_OK) {
        return rc;
    }

    for (uint32_t i = 0; i < view.typeCount; ++i) {
        const uint64_t rec =
            static_cast<uint64_t>(view.typeOffset) +
            static_cast<uint64_t>(i) * kSchemaTypeRecordSize;
        const uint32_t constraintStart = readU32(view.data, rec + 28);
        const uint32_t constraintCount = readU32(view.data, rec + 32);

        ConstraintPack pack = {};
        rc = packConstraints(ctx, view, constraintStart, constraintCount,
                             &pack);
        if (rc != ASN1_OK) {
            schemaDestroy(schema);
            return rc;
        }

        asn1_type_desc_t desc = {};
        desc.struct_size = sizeof(asn1_type_desc_t);
        desc.name = reinterpret_cast<const char *>(
            view.data + readU32(view.data, rec));
        desc.kind = static_cast<asn1_type_kind_t>(
            readU16(view.data, rec + 4));
        desc.tag_class = static_cast<asn1_tag_class_t>(view.data[rec + 8]);
        desc.tag_number = readU32(view.data, rec + 12);
        desc.tag_mode =
            static_cast<asn1_tag_mode_t>(view.data[rec + 6]);
        desc.element_type_id = readU32(view.data, rec + 16);
        desc.flags = view.data[rec + 7];
        desc.constraints = pack.descs;
        desc.constraint_count = pack.count;

        uint32_t typeId = 0;
        rc = schemaAddType(ctx, schema, &desc, &typeId, true);
        freeConstraintPack(ctx, &pack);
        if (rc != ASN1_OK) {
            schemaDestroy(schema);
            return rc;
        }
    }

    for (uint32_t i = 0; i < view.typeCount; ++i) {
        const uint64_t rec =
            static_cast<uint64_t>(view.typeOffset) +
            static_cast<uint64_t>(i) * kSchemaTypeRecordSize;
        const uint32_t fieldStart = readU32(view.data, rec + 20);
        const uint32_t fieldCount = readU32(view.data, rec + 24);
        const uint32_t typeId = i + 1;

        for (uint32_t j = 0; j < fieldCount; ++j) {
            const uint64_t fieldRec =
                static_cast<uint64_t>(view.fieldOffset) +
                static_cast<uint64_t>(fieldStart + j) *
                    kSchemaFieldRecordSize;
            const uint32_t constraintStart =
                readU32(view.data, fieldRec + 16);
            const uint32_t constraintCount =
                readU32(view.data, fieldRec + 20);

            ConstraintPack pack = {};
            rc = packConstraints(ctx, view, constraintStart,
                                 constraintCount, &pack);
            if (rc != ASN1_OK) {
                schemaDestroy(schema);
                return rc;
            }

            asn1_field_desc_t desc = {};
            desc.struct_size = sizeof(asn1_field_desc_t);
            desc.name = reinterpret_cast<const char *>(
                view.data + readU32(view.data, fieldRec));
            desc.type_id = readU32(view.data, fieldRec + 4);
            desc.flags = readU16(view.data, fieldRec + 8);
            const uint32_t defaultIndex =
                readU32(view.data, fieldRec + 12);
            if (defaultIndex != 0) {
                const uint64_t defaultRec =
                    static_cast<uint64_t>(view.defaultOffset) +
                    static_cast<uint64_t>(defaultIndex - 1) *
                        kSchemaDefaultRecordSize;
                const uint32_t dataOffset =
                    readU32(view.data, defaultRec);
                const uint32_t dataSize =
                    readU32(view.data, defaultRec + 4);
                desc.default_value = view.data + dataOffset;
                desc.default_value_size = dataSize;
            }
            desc.field_constraints = pack.descs;
            desc.field_constraint_count = pack.count;

            rc = schemaAddField(ctx, schema, typeId, &desc);
            freeConstraintPack(ctx, &pack);
            if (rc != ASN1_OK) {
                schemaDestroy(schema);
                return rc;
            }
        }
    }

    for (uint32_t i = 0; i < view.nameCount; ++i) {
        const uint64_t rec =
            static_cast<uint64_t>(view.nameOffset) +
            static_cast<uint64_t>(i) * kSchemaNameRecordSize;
        const char *name = reinterpret_cast<const char *>(
            view.data + readU32(view.data, rec + 4));
        rc = schemaAddName(ctx, schema, readU32(view.data, rec), name,
                           readU16(view.data, rec + 8),
                           readU16(view.data, rec + 10),
                           readI64(view.data, rec + 16));
        if (rc != ASN1_OK) {
            schemaDestroy(schema);
            return rc;
        }
    }

    schema->rootTypeId = view.rootTypeId;
    rc = schemaSeal(ctx, schema);
    if (rc != ASN1_OK) {
        schemaDestroy(schema);
        return rc;
    }
    *outSchema = schema;
    return ASN1_OK;
}

} /* namespace */

asn1_err_t schemaLoad(Context *ctx, const asn1_schema_table_t *table,
                      Schema **outSchema) noexcept
{
    *outSchema = nullptr;
    if (table == nullptr || table->data == nullptr || table->size == 0) {
        contextSetError(ctx, ASN1_E_INVALID_ARG, SIZE_MAX, 0);
        return ASN1_E_INVALID_ARG;
    }
    if (table->struct_size != sizeof(asn1_schema_table_t) ||
        table->reserved != 0) {
        contextSetError(ctx, ASN1_E_INVALID_CONFIG, SIZE_MAX, 0);
        return ASN1_E_INVALID_CONFIG;
    }
    if (static_cast<uint64_t>(table->size) > ctx->m_maxInputBytes) {
        contextSetError(ctx, ASN1_E_INPUT_LIMIT, SIZE_MAX, 0);
        return ASN1_E_INPUT_LIMIT;
    }
    if (table->size < kSchemaHeaderSize) {
        contextSetError(ctx, ASN1_E_SCHEMA_FORMAT, 0, 0);
        return ASN1_E_SCHEMA_FORMAT;
    }

    TableView view = {};
    asn1_err_t rc = validateHeader(ctx, table, &view);
    if (rc != ASN1_OK) {
        return rc;
    }
    rc = validateRegions(ctx, view);
    if (rc != ASN1_OK) {
        return rc;
    }
    rc = validateTypeRecords(ctx, view);
    if (rc != ASN1_OK) {
        return rc;
    }
    rc = validateFieldRecords(ctx, view);
    if (rc != ASN1_OK) {
        return rc;
    }
    rc = validateConstraintRecords(ctx, view);
    if (rc != ASN1_OK) {
        return rc;
    }
    rc = validateDefaultRecords(ctx, view);
    if (rc != ASN1_OK) {
        return rc;
    }
    rc = validateNameRecords(ctx, view);
    if (rc != ASN1_OK) {
        return rc;
    }
    return buildTree(ctx, view, outSchema);
}

} /* namespace asn1 */
