/*
 * Copyright (c) 2026 asn1 project contributors
 * SPDX-License-Identifier: MIT
 *
 * libFuzzer harness：DER 解码 → DER 编码 → 再解码 往返。
 * 断言：对 DER 严格解码成功的输入，编码产物必须能再次 DER 解码成功，
 * 且与输入逐字节一致（规范 DER 唯一）。违反即内部不变式破坏，掉 trap。
 */
#include <asn1/asn1.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    asn1_ctx_t *ctx = fuzz_ctx_create();
    if (ctx == NULL) {
        return 0;
    }

    asn1_decode_options_t options;
    asn1_decode_options_init(&options);
    options.struct_size = sizeof(options);
    options.encoding = ASN1_ENCODING_DER;

    asn1_doc_t *doc = NULL;
    size_t consumed = 0;
    asn1_err_t rc = asn1_decode_buffer(ctx, data, size, &options, &doc,
                                       &consumed);
    /* DER 严格解码：输入非法/非最短等返回错误码（含 NON_CANONICAL），正常。 */
    if (rc == ASN1_OK && doc != NULL && consumed == size) {
        asn1_buf_t buf;
        memset(&buf, 0, sizeof(buf));
        if (asn1_encode_buffer(ctx, doc, NULL, &buf) == ASN1_OK) {
            asn1_doc_t *doc2 = NULL;
            size_t consumed2 = 0;
            asn1_err_t rc2 = asn1_decode_buffer(ctx, buf.data, buf.size,
                                                &options, &doc2, &consumed2);
            int identical = (buf.size == size) &&
                            (memcmp(buf.data, data, size) == 0);
            if (rc2 != ASN1_OK || consumed2 != buf.size || !identical) {
                __builtin_trap();
            }
            if (doc2 != NULL) {
                fuzz_walk(asn1_doc_root(doc2));
                asn1_doc_destroy(doc2);
            }
            (void)asn1_buf_release(ctx, &buf);
        }
        asn1_doc_destroy(doc);
    }

    asn1_ctx_destroy(ctx);
    return 0;
}