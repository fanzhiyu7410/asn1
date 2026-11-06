/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asn1-cms 版本查询。版本值只来自 CMake 生成的 cms_version.h。
 */

#include "asn1/cms/cms.h"

extern "C" ASN1_CMS_API const char *asn1_cms_version_string(void)
{
    return ASN1_CMS_VERSION_STRING;
}
