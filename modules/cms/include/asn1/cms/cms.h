/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * asn1-cms 公共头文件（占位骨架）。
 *
 * 本模块承载 RFC 6268（CMS/PKCS#7）的描述表与字段访问 API。
 * 占位阶段只提供版本查询与导出宏，具体函数在二期设计后填入。
 */

#ifndef ASN1_CMS_CMS_H_INCLUDED
#define ASN1_CMS_CMS_H_INCLUDED

/* 由 CMake 从 project(asn1-cms VERSION ...) 生成，源码树中不手写版本宏。 */
#include <asn1/cms/cms_version.h>

#if defined(ASN1_CMS_STATIC)
#define ASN1_CMS_API
#elif defined(_WIN32) || defined(__CYGWIN__)
#if defined(ASN1_CMS_BUILDING_LIBRARY)
#define ASN1_CMS_API __declspec(dllexport)
#else
#define ASN1_CMS_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) && __GNUC__ >= 4
#define ASN1_CMS_API __attribute__((visibility("default")))
#else
#define ASN1_CMS_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* 返回模块版本字符串；静态存储，调用方不得释放。 */
ASN1_CMS_API const char *asn1_cms_version_string(void);

#ifdef __cplusplus
}
#endif

#endif /* ASN1_CMS_CMS_H_INCLUDED */
