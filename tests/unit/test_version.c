/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * 版本查询与自检的最小单元断言。
 */
#include <asn1/asn1.h>

#include <string.h>

#include "check.h"

int main(void)
{
    asn1_version_info_t info;
    info.struct_size = sizeof(info);

    ASN1_TEST_CHECK(asn1_version(&info) == ASN1_OK);
    ASN1_TEST_CHECK(info.struct_size == sizeof(info));
    ASN1_TEST_CHECK(info.major == ASN1_VERSION_MAJOR);
    ASN1_TEST_CHECK(info.minor == ASN1_VERSION_MINOR);
    ASN1_TEST_CHECK(info.patch == ASN1_VERSION_PATCH);
    ASN1_TEST_CHECK(info.reserved == 0);
    ASN1_TEST_CHECK(info.string != NULL);
    ASN1_TEST_CHECK(strcmp(info.string, ASN1_VERSION_STRING) == 0);

    ASN1_TEST_CHECK(asn1_version_check(ASN1_VERSION_MAJOR, ASN1_VERSION_MINOR) == ASN1_OK);
    ASN1_TEST_CHECK(asn1_version_check(ASN1_VERSION_MAJOR + 1u, ASN1_VERSION_MINOR) ==
                    ASN1_E_VERSION_MISMATCH);

    info.struct_size = 0;
    ASN1_TEST_CHECK(asn1_version(&info) == ASN1_E_INVALID_CONFIG);
    ASN1_TEST_CHECK(asn1_version(NULL) == ASN1_E_INVALID_ARG);

    return 0;
}
