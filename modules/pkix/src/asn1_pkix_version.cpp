/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asn1-pkix 版本查询。版本值只来自 CMake 生成的 pkix_version.h。
 */

#include "asn1/pkix/pkix.h"

extern "C" ASN1_PKIX_API const char *asn1_pkix_version_string(void)
{
    return ASN1_PKIX_VERSION_STRING;
}
