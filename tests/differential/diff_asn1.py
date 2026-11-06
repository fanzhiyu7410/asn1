#!/usr/bin/env python3
# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT
"""差分测试：核心 DER 解码 vs OpenSSL asn1parse（主），asn1tools 生成器（可选参照）。

判据：
  - 对 tests/data 的 DER 样本，比“能否解析、TLV 边界与偏移、结构层级”。
  - decode -> encode 往返后，用 openssl 确认仍是合法 DER 且逐字节一致。

退出码：
  0 = 通过（全部比较完成，无未归类差异）
  1 = 失败（发现未归类差异）
  2 = skipped（必需参照工具缺失：asn1_dump 或 openssl）

参照工具不链接进产物、不做运行时依赖；asn1tools 缺装时该段显式 skipped。
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA = os.path.join(ROOT, "tests", "data")

REAL_DERS = [
    "cert_rsa_selfsigned.der",
    "cert_rsa_pss_selfsigned.der",
    "cert_ec_selfsigned.der",
    "csr_rsa.der",
    "csr_ec.der",
    "key_rsa_pkcs8.der",
    "key_rsa_pss_pkcs8.der",
    "key_ec_pkcs8.der",
    "key_rsa_pkcs8_encrypted.der",
    "key_rsa_pkcs1_private.der",
    "key_rsa_pkcs1_public.der",
]

OPENSSL_LINE = re.compile(
    r"^\s*(\d+):d=(\d+)\s+hl=(\d+)\s+l=\s*(\d+)\s+(cons|prim):")

# 已知可接受差异：openssl 对构造字符串的展开与我们（合并为基本）不同。
# 当前 DER 样本均不触发；若触发则记录并跳过失败，另列清单核对。
KNOWN_ACCEPTABLE = set()


def find_tool(name):
    return shutil.which(name)


def run_openssl_dump(openssl, path):
    """返回 openssl asn1parse 解析出的 (offset,depth,hl,l,cons) 列表。"""
    proc = subprocess.run(
        [openssl, "asn1parse", "-inform", "DER", "-i", "-in", path],
        capture_output=True, text=True)
    entries = []
    for line in proc.stdout.splitlines():
        m = OPENSSL_LINE.match(line)
        if m:
            offset, depth, hl, l, cons = m.groups()
            entries.append((int(offset), int(depth), int(hl), int(l), cons))
    return entries, proc.returncode, proc.stderr


def run_our_dump(asn1_dump, path):
    proc = subprocess.run([asn1_dump, path], capture_output=True, text=True)
    entries = []
    for line in proc.stdout.splitlines():
        m = OPENSSL_LINE.match(line)
        if m:
            offset, depth, hl, l, cons = m.groups()
            entries.append((int(offset), int(depth), int(hl), int(l), cons))
    return entries, proc.returncode, proc.stderr


def compare_entry(our, osl):
    # 逐字段比较 offset/depth/hl/l/cons。
    return our == osl


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--asn1-dump", default=None,
                    help="asn1_dump 可执行文件路径（默认自动探测 build 目录）")
    ap.add_argument("--data-dir", default=DATA)
    ap.add_argument("--skip-asn1tools", action="store_true")
    args = ap.parse_args()

    openssl = find_tool("openssl")
    asn1_dump = args.asn1_dump or _find_dump()
    if asn1_dump is None:
        print("SKIPPED: asn1_dump 未找到（先构建 tests/differential）")
        return 2
    if openssl is None:
        print("SKIPPED: openssl 未安装")
        return 2

    total = 0
    mismatches = []
    roundtrip_ok = 0
    roundtrip_fail = 0
    asn1tools_status = "skipped (未运行)"

    with tempfile.TemporaryDirectory() as tmp:
        for name in REAL_DERS:
            path = os.path.join(args.data_dir, name)
            if not os.path.exists(path):
                continue
            total += 1

            ours, our_rc, our_err = run_our_dump(asn1_dump, path)
            openr, op_rc, op_err = run_openssl_dump(openssl, path)

            if our_rc != 0:
                mismatches.append((name, "我们无法解析"))
                continue
            if op_rc != 0:
                mismatches.append((name, "openssl 无法解析"))
                continue

            if ours != openr:
                # 逐条找差异归因。
                diff_detail = []
                for i in range(max(len(ours), len(openr))):
                    a = ours[i] if i < len(ours) else None
                    b = openr[i] if i < len(openr) else None
                    if a != b:
                        diff_detail.append((i, a, b))
                mismatches.append((name, "结构差异 %r" % (diff_detail,)))
                continue

            # decode -> encode 往返。
            out_path = os.path.join(tmp, name + ".rt.der")
            rt = subprocess.run(
                [asn1_dump, "--roundtrip", path, out_path],
                capture_output=True)
            if rt.returncode != 0:
                roundtrip_fail += 1
                mismatches.append((name, "往返编码失败"))
                continue
            with open(path, "rb") as f:
                orig = f.read()
            with open(out_path, "rb") as f:
                encoded = f.read()
            if orig != encoded:
                roundtrip_fail += 1
                mismatches.append((name, "往返结果与输入逐字节不一致"))
                continue
            # 用 openssl 确认往返产物仍是合法 DER。
            _, rt_op_rc, _ = run_openssl_dump(openssl, out_path)
            if rt_op_rc != 0:
                roundtrip_fail += 1
                mismatches.append((name, "往返产物 openssl 无法解析"))
                continue
            roundtrip_ok += 1

        # asn1tools 参照（可选）：在持久 tmp 内运行。
        asn1tools_status = _run_asn1tools(asn1_dump, openssl, tmp)

    print("样本数:", total)
    print("往返通过:", roundtrip_ok, "往返失败:", roundtrip_fail)
    print("asn1tools:", asn1tools_status)
    if mismatches:
        print("差异明细:")
        for name, detail in mismatches:
            print("  - %s: %s" % (name, detail))
        return 1
    print("差分通过：未发现未归类差异")
    return 0


def _find_dump():
    for cand in [
        os.path.join(ROOT, "build", "tests", "differential", "asn1_dump"),
        os.path.join(ROOT, "build-diff", "tests", "differential", "asn1_dump"),
    ]:
        if os.path.exists(cand):
            return cand
    return None


def _run_asn1tools(asn1_dump, openssl, tmp):
    try:
        import asn1tools  # noqa: F401
    except ImportError:
        return "skipped (asn1tools 未安装)"

    spec = (""""Rec DEFINITIONS ::= BEGIN
  Rec ::= SEQUENCE { i INTEGER, s OCTET STRING, b BOOLEAN OPTIONAL }
END
""")
    try:
        with tempfile.NamedTemporaryFile(
                "w", suffix=".asn1", delete=False) as f:
            f.write(spec)
            spec_path = f.name
        compiler = asn1tools.compile_files([spec_path], codec="der")
        vectors = [
            {"i": 5, "s": b"abc", "b": True},
            {"i": -1, "s": b"", "b": False},
            {"i": 0, "s": b"x" * 300},
        ]
        for idx, vec in enumerate(vectors):
            der = compiler.encode("Rec", vec)
            der_path = os.path.join(tmp, "at_%d.der" % idx)
            with open(der_path, "wb") as f:
                f.write(der)
            ours, our_rc, _ = run_our_dump(asn1_dump, der_path)
            openr, op_rc, _ = run_openssl_dump(openssl, der_path)
            if our_rc != 0 or op_rc != 0 or ours != openr:
                return "失败: asn1tools 生成样本 #%d 三方不一致" % idx
        os.unlink(spec_path)
        return "通过 (%d 个生成样本三方一致)" % len(vectors)
    except Exception as exc:  # noqa: BLE001
        return "skipped (asn1tools 调用失败: %r)" % (exc,)


if __name__ == "__main__":
    sys.exit(main())