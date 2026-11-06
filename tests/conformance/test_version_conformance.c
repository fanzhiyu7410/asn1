/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * 生成头、运行期版本与版本编号规则三者的一致性断言。
 */
#include <asn1/asn1.h>

#include <stdio.h>
#include <string.h>

#include "check.h"

int main(void)
{
    asn1_version_info_t info;
    char expected[64];

    info.struct_size = sizeof(info);
    ASN1_TEST_CHECK(asn1_version(&info) == ASN1_OK);

    (void)snprintf(expected, sizeof(expected), "%u.%u.%u",
                   (unsigned)ASN1_VERSION_MAJOR,
                   (unsigned)ASN1_VERSION_MINOR,
                   (unsigned)ASN1_VERSION_PATCH);

    ASN1_TEST_CHECK(strcmp(expected, ASN1_VERSION_STRING) == 0);
    ASN1_TEST_CHECK(strcmp(info.string, expected) == 0);
    ASN1_TEST_CHECK(ASN1_VERSION_ENCODED ==
                    ((ASN1_VERSION_MAJOR << 16) | (ASN1_VERSION_MINOR << 8) |
                     ASN1_VERSION_PATCH));

    /* 次版本差异视为兼容，只有主版本不一致才失败。 */
    ASN1_TEST_CHECK(asn1_version_check(ASN1_VERSION_MAJOR, ASN1_VERSION_MINOR + 1u) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_version_check(ASN1_VERSION_MAJOR + 1u, ASN1_VERSION_MINOR) ==
                    ASN1_E_VERSION_MISMATCH);

    return 0;
}
