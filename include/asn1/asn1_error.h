/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * 错误码与错误详情。错误码表与分类见 docs/05-错误模型.md；错误详情字段
 * 语义见 docs/02-C-API规范.md 第 7 节。
 *
 * 本头文件不声明任何函数；错误状态通过 asn1/asn1_allocator.h 中的上下文
 * 接口读取与清除。
 */
#ifndef ASN1_ASN1_ERROR_H_INCLUDED
#define ASN1_ASN1_ERROR_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

typedef int32_t asn1_err_t;

/* 成功。 */
#define ASN1_OK ((asn1_err_t)0)

/* 调用/配置错误（1000–1999）。 */
#define ASN1_E_INVALID_ARG ((asn1_err_t)1001)
#define ASN1_E_INVALID_CONFIG ((asn1_err_t)1002)
#define ASN1_E_INVALID_STATE ((asn1_err_t)1003)
#define ASN1_E_UNSUPPORTED ((asn1_err_t)1004)
#define ASN1_E_VERSION_MISMATCH ((asn1_err_t)1005)

/* 内存错误（2000–2999）。 */
#define ASN1_E_NOMEM ((asn1_err_t)2001)
#define ASN1_E_MEMORY_LIMIT ((asn1_err_t)2002)
#define ASN1_E_STATIC_POOL_EXHAUSTED ((asn1_err_t)2003)

/* 解码/数据错误（3000–3999）。 */
#define ASN1_E_TRUNCATED ((asn1_err_t)3001)
#define ASN1_E_MALFORMED_TAG ((asn1_err_t)3002)
#define ASN1_E_MALFORMED_LENGTH ((asn1_err_t)3003)
#define ASN1_E_LENGTH_MISMATCH ((asn1_err_t)3004)
#define ASN1_E_INDEFINITE_NOT_ALLOWED ((asn1_err_t)3005)
#define ASN1_E_TRAILING_DATA ((asn1_err_t)3006)
#define ASN1_E_MALFORMED_VALUE ((asn1_err_t)3007)
#define ASN1_E_NON_CANONICAL ((asn1_err_t)3008)

/* 编码/值错误（4000–4999）。 */
#define ASN1_E_UNSUPPORTED_ENCODING ((asn1_err_t)4001)
#define ASN1_E_INVALID_VALUE ((asn1_err_t)4002)
#define ASN1_E_RANGE ((asn1_err_t)4003)
#define ASN1_E_CONVERSION ((asn1_err_t)4004)

/* 资源上限（5000–5999）。 */
#define ASN1_E_DEPTH_LIMIT ((asn1_err_t)5001)
#define ASN1_E_NODE_LIMIT ((asn1_err_t)5002)
#define ASN1_E_INPUT_LIMIT ((asn1_err_t)5003)
#define ASN1_E_OUTPUT_LIMIT ((asn1_err_t)5004)

/* IO/回调错误（6000–6999）。 */
#define ASN1_E_IO_READ ((asn1_err_t)6001)
#define ASN1_E_IO_WRITE ((asn1_err_t)6002)

/* 模板/模式校验（7000–7999）。 */
#define ASN1_E_SCHEMA_FORMAT ((asn1_err_t)7001)
#define ASN1_E_SCHEMA_TYPE ((asn1_err_t)7002)
#define ASN1_E_SCHEMA_FIELD ((asn1_err_t)7003)
#define ASN1_E_SCHEMA_CONSTRAINT ((asn1_err_t)7004)
#define ASN1_E_SCHEMA_DEFAULT ((asn1_err_t)7005)

/* 内部错误（8000–8999）。 */
#define ASN1_E_INTERNAL ((asn1_err_t)8001)

/*
 * 错误详情。调用方必须把 struct_size 初始化为 sizeof(asn1_error_info_t)。
 * 成功读取（asn1_ctx_get_error 返回 ASN1_OK）时各字段按下表填充：
 * 无错误时 code = ASN1_OK、message = NULL、callback_code = 0、
 * offset = SIZE_MAX、depth = 0、path = NULL。
 */
typedef struct asn1_error_info {
    size_t struct_size;      /* 输入：必须为 sizeof(asn1_error_info_t) */
    asn1_err_t code;         /* 最近一次失败的稳定错误码 */
    int32_t callback_code;   /* 原始 reader/writer 回调错误码；无则为 0 */
    const char *message;     /* 静态英文短消息；无错误为 NULL */
    size_t offset;           /* 输入字节偏移；无意义时为 SIZE_MAX */
    uint32_t depth;          /* 出错时的嵌套深度；无意义时为 0 */
    uint32_t reserved;       /* 必须置零 */
    const char *path;        /* schema 字段路径；无 schema 或无法定位时为 NULL */
} asn1_error_info_t;

#endif /* ASN1_ASN1_ERROR_H_INCLUDED */
