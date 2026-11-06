/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 版本与能力查询。版本值只来自 CMake 生成的 asn1_version.h，
 * 不在源码中手写版本号。
 */

#include <asn1/asn1.h>

namespace {

/* 已验收能力位：schema 加载/注册、严格校验、告警、BER 构造字符串、
 * 时间纳秒、大整数十进制、schema 感知编码、ANY/开放类型与名称表查询。
 * CER/PER 尚未实现，保持未置位。 */
constexpr uint64_t kCapabilities =
    (UINT64_C(1) << 0) |  /* ASN1_CAP_SCHEMA_TABLE_LOAD */
    (UINT64_C(1) << 1) |  /* ASN1_CAP_SCHEMA_RUNTIME_REGISTER */
    (UINT64_C(1) << 2) |  /* ASN1_CAP_STRICT_SCHEMA */
    (UINT64_C(1) << 3) |  /* ASN1_CAP_WARNING */
    (UINT64_C(1) << 4) |  /* ASN1_CAP_BER_CONSTRUCTED_STRING */
    (UINT64_C(1) << 5) |  /* ASN1_CAP_TIME_NANOSECOND */
    (UINT64_C(1) << 6) |  /* ASN1_CAP_BIGINT_DECIMAL */
    (UINT64_C(1) << 7) |  /* ASN1_CAP_ENCODE_SCHEMA_AWARE */
    (UINT64_C(1) << 10) | /* ASN1_CAP_ANY_OPEN_TYPE */
    (UINT64_C(1) << 11);  /* ASN1_CAP_SCHEMA_NAMES */

/* 已定义的 12 个能力位（0–11），用于拒绝未定义位查询。 */
constexpr uint64_t kKnownCapabilities = (UINT64_C(1) << 12) - 1;

} /* namespace */

extern "C" {

ASN1_API asn1_err_t asn1_version(asn1_version_info_t *out_info)
{
    if (out_info == nullptr) {
        return ASN1_E_INVALID_ARG;
    }
    if (out_info->struct_size != sizeof(asn1_version_info_t)) {
        return ASN1_E_INVALID_CONFIG;
    }

    asn1_version_info_t info{};
    info.struct_size = sizeof(asn1_version_info_t);
    info.major = ASN1_VERSION_MAJOR;
    info.minor = ASN1_VERSION_MINOR;
    info.patch = ASN1_VERSION_PATCH;
    info.reserved = 0;
    info.string = ASN1_VERSION_STRING;
    info.capabilities = kCapabilities;

    *out_info = info;
    return ASN1_OK;
}

ASN1_API asn1_err_t asn1_version_check(uint32_t expected_major,
                                       uint32_t expected_minor)
{
    /* 次版本只保留用于诊断与未来策略，不参与失败判定。 */
    (void)expected_minor;

    if (expected_major != ASN1_VERSION_MAJOR) {
        return ASN1_E_VERSION_MISMATCH;
    }
    return ASN1_OK;
}

ASN1_API int asn1_has_capability(uint64_t capability)
{
    /* 只接受单个已定义位；0、多位组合与未定义位均返回 0。 */
    if (capability == 0 || (capability & (capability - UINT64_C(1))) != 0) {
        return 0;
    }
    if ((capability & ~kKnownCapabilities) != 0) {
        return 0;
    }
    return (kCapabilities & capability) != 0 ? 1 : 0;
}

} /* extern "C" */
