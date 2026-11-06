/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 */

/*
 * BER 解码器内部入口。
 *
 * 职责：解析确定长度的完整 TLV 并构建文档树。
 * 依赖：types/asn1_dom.h 与 core/asn1_context.h。
 * 约束：递归深度受 maxDepth 约束；不使用异常；失败时不返回部分文档。
 */
#ifndef ASN1_SRC_BER_ASN1_BER_DECODER_H_INCLUDED
#define ASN1_SRC_BER_ASN1_BER_DECODER_H_INCLUDED

#include <asn1/asn1.h>

#include <cstddef>
#include <cstdint>

#include "../core/asn1_context.h"
#include "../types/asn1_dom.h"

namespace asn1 {

/*
 * 解码一块输入。
 * copyInput：把输入复制到文档 arena；allowTrailing：允许顶层 TLV 之后有字节。
 * 成功时 *outDoc 非 NULL 并写 *consumed（若不为 NULL）；失败时 *outDoc 为 NULL，
 * *consumed 不修改。
 */
asn1_err_t decodeBuffer(Context *ctx, const uint8_t *data, size_t size,
                        uint32_t maxDepth, bool copyInput,
                        bool allowTrailing, asn1_encoding_t encoding,
                        Document **outDoc, size_t *consumed) noexcept;

/*
 * 把 reader 的数据分段读满至 EOF。
 * 成功时 *outBuffer 为上下文级分配（调用方用 contextRelease 释放），
 * *outUsed 为实际拉取字节数；失败时 *outBuffer 为 NULL、*outUsed 为 0。
 * 回调返回非零时包装为 ASN1_E_IO_READ，原始码写入上下文的 callback_code。
 * 拉取总量超过 m_maxInputBytes 返回 ASN1_E_INPUT_LIMIT。
 */
asn1_err_t readReaderInput(Context *ctx, const asn1_reader_t *reader,
                           uint8_t **outBuffer, size_t *outUsed) noexcept;

} /* namespace asn1 */

#endif /* ASN1_SRC_BER_ASN1_BER_DECODER_H_INCLUDED */
