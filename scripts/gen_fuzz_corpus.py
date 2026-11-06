#!/usr/bin/env python3
# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT
"""确定性生成 libFuzzer 种子语料到 tests/fuzz/corpus/<harness>/。

只依赖标准库；纯确定性。产物体积小，检入仓库供 CI 复用。
扩展方式见 tests/fuzz/README.md。
"""
import os
import shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "tests", "data")
CORPUS = os.path.join(ROOT, "tests", "fuzz", "corpus")
PKIX_BIN = os.path.join(ROOT, "modules", "pkix", "generated", "pkix_schema.bin")

# 需要二进制种子（DER/BER）的 harness。
BIN_HARNESSES = [
    "decode_ber",
    "decode_der",
    "reader",
    "schema_decode",
    "roundtrip",
]

# 真实 DER 样本（tests/data 下的 .der）。
REAL_DERS = [
    "cert_rsa_selfsigned.der",
    "cert_rsa_pss_selfsigned.der",
    "cert_ec_selfsigned.der",
    "csr_rsa.der",
    "csr_ec.der",
    "key_rsa_pkcs8.der",
    "key_rsa_pss_pkcs8.der",
    "key_ec_pkcs8.der",
]

# 合成二进制种子：覆盖未知扩展/ANY 三形态/EXPLICIT ANY/不定长（单层+嵌套）/
# 截断/超长长度/多字节 tag/SET 乱序/非最短长度/时间变体/空输入 等。
SYNTH_BINARY = {
    "empty": b"",
    "null_any": b"\x05\x00",
    "seq_int": b"\x30\x03\x02\x01\x05",
    "seq_two_int": b"\x30\x06\x02\x01\x05\x02\x01\x00",
    "indefinite_seq": b"\x30\x80\x02\x01\x05\x00\x00",
    "indefinite_nested": b"\x30\x80\x30\x80\x02\x01\x05\x00\x00\x00\x00",
    "indefinite_missing_eoc": b"\x30\x80\x02\x01\x05",
    "trunc_struct": b"\x30\x06\x02\x01\x05",
    "trunc_header": b"\x30",
    "long_len_4byte_zero": b"\x30\x84\x00\x00\x00\x00",
    "long_len_claim_huge": b"\x30\x84\x7f\xff\xff\xff",
    "long_len_1byte": b"\x30\x81\x80",
    "multi_tag_128": b"\x1f\x81\x00\x00",
    "multi_tag_16383": b"\x1f\xff\x7f\x00",
    "multi_tag_trunc": b"\x1f\x81",
    "set_unordered": b"\x31\x06\x02\x01\x05\x02\x01\x00",
    "non_minimal_len_int": b"\x02\x81\x01\x05",
    "non_minimal_len_seq": b"\x30\x81\x03\x02\x01\x05",
    "explicit_any": b"\xa0\x03\x02\x01\x05",
    "explicit_any_nested": b"\xa0\x07\x30\x03\x02\x01\x05",
    "context_constructed": b"\xa1\x03\x02\x01\x05",
    "context_primitive": b"\x83\x01\x05",
    "unknown_ext": b"\xa3\x05\x30\x03\x02\x01\x01",
    "boolean_true": b"\x01\x01\xff",
    "boolean_bad": b"\x01\x01\x01",
    "oid_ec_p256": b"\x06\x07\x2a\x86\x48\xce\x3d\x04\x01",
    "utctime_z": b"\x17\x0d" + b"250101000000Z",
    "gentime_z": b"\x18\x0f" + b"20250101000000Z",
    "gentime_frac": b"\x18\x11" + b"20250101000000.5Z",
    "time_bad_char": b"\x17\x0d" + b"2501010000XXZ",
    "eoc_only": b"\x00\x00",
    "eoc_misplaced": b"\x00\x00\x05\x00",
    "octet_constructed": b"\x24\x80\x04\x02ab\x00\x00",
    "high_tag_private": b"\xdf\x81\x00\x00",
}

# asn1c 文本 harness 的种子（.asn1 文本）。
ASN1C_DIR = os.path.join(DATA, "asn1c")
ASN1C_SEEDS = ["equiv_sample.asn1"] + [
    os.path.join("negative", f)
    for f in sorted(os.listdir(os.path.join(ASN1C_DIR, "negative")))
]

SYNTH_ASN1C = {
    "empty": "",
    "minimal_module": "M DEFINITIONS ::= BEGIN END\n",
    "junk": "@@@ ### $$$",
    "truncated_module": "M DEFINITIONS ::= BEGIN\nT ::= SEQUENCE {\n",
    "seq_module": ("M DEFINITIONS EXPLICIT TAGS ::= BEGIN\n"
                   "T ::= SEQUENCE { a INTEGER OPTIONAL, b OCTET STRING }\n"
                   "END\n"),
}


def write_bytes(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def write_text(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def main():
    # 1) 二进制 harness：真实 DER + 合成二进制种子。
    for h in BIN_HARNESSES:
        hdir = os.path.join(CORPUS, h)
        for name in REAL_DERS:
            src = os.path.join(DATA, name)
            write_bytes(os.path.join(hdir, name), open(src, "rb").read())
        for name, data in SYNTH_BINARY.items():
            write_bytes(os.path.join(hdir, name), data)

    # 2) schema_load：真实 PKIX 表字节（最大攻击面）+ 空/垃圾。
    hdir = os.path.join(CORPUS, "schema_load")
    write_bytes(os.path.join(hdir, "pkix_schema.bin"),
                open(PKIX_BIN, "rb").read())
    write_bytes(os.path.join(hdir, "empty"), b"")
    write_bytes(os.path.join(hdir, "magic_only"), b"ASN1SCH")
    write_bytes(os.path.join(hdir, "garbage"), b"\xde\xad\xbe\xef" * 16)

    # 3) asn1c 文本 harness。
    hdir = os.path.join(CORPUS, "asn1c")
    for name in ASN1C_SEEDS:
        src = os.path.join(ASN1C_DIR, name)
        write_text(os.path.join(hdir, name.replace("/", "_")),
                   open(src, encoding="utf-8").read())
    for name, text in SYNTH_ASN1C.items():
        write_text(os.path.join(hdir, name), text)

    print("corpus generated under", CORPUS)


if __name__ == "__main__":
    main()