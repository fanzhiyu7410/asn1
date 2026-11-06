/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * 以 C99 编译器和公共头验证 C ABI 的版本查询与能力位行为。
 */
#include <asn1/asn1.h>

#include <string.h>

#include "check.h"

int main(void)
{
    asn1_version_info_t info;
    info.struct_size = sizeof(asn1_version_info_t);

    ASN1_TEST_CHECK(asn1_version(&info) == ASN1_OK);
    ASN1_TEST_CHECK(info.struct_size == sizeof(asn1_version_info_t));
    ASN1_TEST_CHECK(info.reserved == 0);
    ASN1_TEST_CHECK(info.string != NULL);
    /* 已验收能力位全部置位；CER/PER 仍为保留位。 */
    const uint64_t expected = ASN1_CAP_SCHEMA_TABLE_LOAD |
                              ASN1_CAP_SCHEMA_RUNTIME_REGISTER |
                              ASN1_CAP_STRICT_SCHEMA | ASN1_CAP_WARNING |
                              ASN1_CAP_BER_CONSTRUCTED_STRING |
                              ASN1_CAP_TIME_NANOSECOND |
                              ASN1_CAP_BIGINT_DECIMAL |
                              ASN1_CAP_ENCODE_SCHEMA_AWARE |
                              ASN1_CAP_ANY_OPEN_TYPE |
                              ASN1_CAP_SCHEMA_NAMES;
    ASN1_TEST_CHECK(info.capabilities == expected);
    ASN1_TEST_CHECK(asn1_has_capability(ASN1_CAP_SCHEMA_NAMES) == 1);
    ASN1_TEST_CHECK(asn1_has_capability(ASN1_CAP_ANY_OPEN_TYPE) == 1);
    ASN1_TEST_CHECK(asn1_has_capability(ASN1_CAP_ENCODE_SCHEMA_AWARE) == 1);

    /* 0、多位组合与未定义位一律返回 0。 */
    ASN1_TEST_CHECK(asn1_has_capability(0) == 0);
    ASN1_TEST_CHECK(asn1_has_capability(ASN1_CAP_CER | ASN1_CAP_PER) == 0);
    ASN1_TEST_CHECK(asn1_has_capability(UINT64_C(1) << 63) == 0);

    ASN1_TEST_CHECK(asn1_version_check(ASN1_VERSION_MAJOR, ASN1_VERSION_MINOR) == ASN1_OK);
    ASN1_TEST_CHECK(strcmp(info.string, ASN1_VERSION_STRING) == 0);

    return 0;
}
