/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asn1-pkcs 版本查询。版本值只来自 CMake 生成的 pkcs_version.h。
 */

#include "asn1/pkcs/pkcs.h"

extern "C" ASN1_PKCS_API const char *asn1_pkcs_version_string(void)
{
    return ASN1_PKCS_VERSION_STRING;
}
