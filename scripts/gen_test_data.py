#!/usr/bin/env python3
# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT
"""生成 tests/data/ 下的真实 ASN.1 测试材料。

只依赖 openssl 命令行与 Python 标准库，不引入第三方依赖。

用法：
    python scripts/gen_test_data.py            # 重新生成全部材料与 C 数组头
    python scripts/gen_test_data.py --headers  # 只从已有 .der 重新生成 C 数组头
    python scripts/gen_test_data.py --derived  # 只从已有 key_rsa_pkcs8.pem 派生
                                               # PKCS#1 公私钥与加密 PKCS#8 材料
    python scripts/gen_test_data.py --cms      # 只用已有证书/私钥生成 CMS 样本

产物：
    tests/data/*.pem  PEM 文本材料（自签名证书、私钥、CSR）
    tests/data/*.der  DER 二进制材料（证书、PKCS#8 私钥、PKCS#1 公私钥、CSR）
    tests/data/*.h    由 .der 转换出的 C 数组头，供零第三方 C 测试直接 include
    tests/data/README.md 材料来源与重现说明

注意：密钥与签名含随机成分，重新生成得到的字节与仓库内已提交的版本不同；
测试只依赖“解码→编码逐字节一致”的自洽性，不依赖固定字节。仓库内已提交的
.der/.h 是权威快照，--headers 模式可避免重新生成密钥。
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "tests" / "data"
OPENSSL = os.environ.get("OPENSSL", "openssl")

# 最小 openssl 配置，避免系统默认配置里的 v3_ca 扩展干扰生成。
MINIMAL_CONFIG = """[ req ]
default_md = sha256
distinguished_name = dn
[ dn ]
"""

_CONFIG_PATH = None

# 材料清单：(C 标识符词干, PEM 文件, DER 文件, 生成命令参数, 说明)
CERTS = [
    (
        "cert_rsa_selfsigned",
        "RSA-2048 自签名证书",
        ["-new", "-x509", "-sha256", "-days", "3650",
         "-subj", "/C=CN/O=ASN1 Test/CN=ASN1 RSA Self Signed",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "subjectAltName=DNS:asn1-rsa.example"],
        "key_rsa_pkcs8.pem",
    ),
    (
        "cert_ec_selfsigned",
        "ECDSA P-256 自签名证书",
        ["-new", "-x509", "-sha256", "-days", "3650",
         "-subj", "/C=CN/O=ASN1 Test/CN=ASN1 EC Self Signed",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "subjectAltName=DNS:asn1-ec.example"],
        "key_ec_pkcs8.pem",
    ),
    (
        "cert_rsa_pss_selfsigned",
        "RSA-PSS 自签名证书（AlgorithmIdentifier.parameters 为 SEQUENCE）",
        ["-new", "-x509", "-sha256", "-days", "3650",
         "-subj", "/C=CN/O=ASN1 Test/CN=ASN1 RSA-PSS Self Signed",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "subjectAltName=DNS:asn1-rsa-pss.example"],
        "key_rsa_pss_pkcs8.pem",
    ),
]

CSRS = [
    (
        "csr_rsa",
        "RSA-2048 证书请求",
        "/C=CN/O=ASN1 Test/CN=ASN1 RSA CSR",
        "key_rsa_pkcs8.pem",
    ),
    (
        "csr_ec",
        "ECDSA P-256 证书请求",
        "/C=CN/O=ASN1 Test/CN=ASN1 EC CSR",
        "key_ec_pkcs8.pem",
    ),
]

KEYS = [
    (
        "key_rsa_pkcs8",
        "RSA-2048 私钥（PKCS#8，未加密）",
        ["genpkey", "-algorithm", "RSA",
         "-pkeyopt", "rsa_keygen_bits:2048"],
    ),
    (
        "key_ec_pkcs8",
        "ECDSA P-256 私钥（PKCS#8，未加密）",
        ["genpkey", "-algorithm", "EC",
         "-pkeyopt", "ec_paramgen_curve:P-256"],
    ),
    (
        "key_rsa_pss_pkcs8",
        "RSA-PSS 2048 私钥（PKCS#8，未加密）",
        ["genpkey", "-algorithm", "RSA-PSS",
         "-pkeyopt", "rsa_keygen_bits:2048"],
    ),
]


# 派生材料：只依赖已提交的 key_rsa_pkcs8.pem，不重新生成密钥。
# (C 标识符词干, 说明, 类型)
DERIVED = [
    (
        "key_rsa_pkcs1_private",
        "RSA-2048 私钥（PKCS#1，传统格式）",
        "rsa_private",
    ),
    (
        "key_rsa_pkcs1_public",
        "RSA-2048 公钥（PKCS#1）",
        "rsa_public",
    ),
    (
        "key_rsa_pkcs8_encrypted",
        "RSA-2048 私钥（PKCS#8，PBES2 / AES-256-CBC 加密）",
        "pkcs8_encrypted",
    ),
]

ENCRYPTED_PASSPHRASE = "asn1-test"

# CMS 样本：复用已提交的证书与私钥，不生成新密钥。
# (C 标识符词干, 说明, 签名者参数, 附加参数)
CMS_SAMPLES = [
    (
        "cms_rsa_attached",
        "RSA SignedData，attached（含 eContent、证书、signedAttrs）",
        [("cert_rsa_selfsigned.pem", "key_rsa_pkcs8.pem")],
        ["-nodetach"],
    ),
    (
        "cms_rsa_detached",
        "RSA SignedData，detached（无 eContent，含证书、signedAttrs）",
        [("cert_rsa_selfsigned.pem", "key_rsa_pkcs8.pem")],
        [],
    ),
    (
        "cms_rsa_minimal",
        "RSA SignedData 最小样本（无证书、无 signedAttrs、detached）",
        [("cert_rsa_selfsigned.pem", "key_rsa_pkcs8.pem")],
        ["-nocerts", "-noattr"],
    ),
    (
        "cms_rsa_ec_multicert",
        "RSA + ECDSA 双签名者 SignedData（多证书，attached）",
        [("cert_rsa_selfsigned.pem", "key_rsa_pkcs8.pem"),
         ("cert_ec_selfsigned.pem", "key_ec_pkcs8.pem")],
        ["-nodetach"],
    ),
    (
        "cms_rsa_keyid",
        "RSA SignedData，SignerIdentifier 使用 subjectKeyIdentifier",
        [("cert_rsa_selfsigned.pem", "key_rsa_pkcs8.pem")],
        ["-keyid"],
    ),
]

CMS_CONTENT = b"asn1-cms differential and structure test content\n"


def run_openssl(args):
    """调用 openssl，失败时给出可读错误。"""
    command = [OPENSSL] + args
    result = subprocess.run(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    if result.returncode != 0:
        sys.stderr.write("openssl 调用失败：%s\n" % " ".join(command))
        sys.stderr.write(result.stderr.decode("utf-8", "replace"))
        raise SystemExit(1)


def minimal_config():
    """返回最小 openssl 配置路径；进程内复用。"""
    global _CONFIG_PATH
    if _CONFIG_PATH is None:
        handle, path = tempfile.mkstemp(prefix="asn1-openssl-", suffix=".cnf")
        with os.fdopen(handle, "w", encoding="ascii") as stream:
            stream.write(MINIMAL_CONFIG)
        _CONFIG_PATH = path
    return _CONFIG_PATH


def generate_keys():
    for stem, description, args in KEYS:
        pem_path = DATA_DIR / (stem + ".pem")
        der_path = DATA_DIR / (stem + ".der")
        run_openssl(args + ["-out", str(pem_path)])
        # openssl pkey 默认写出 PKCS#8；DER 形式用于测试解码。
        run_openssl(["pkey", "-in", str(pem_path),
                     "-outform", "DER", "-out", str(der_path)])


def generate_csrs():
    for stem, description, subject, key_file in CSRS:
        pem_path = DATA_DIR / (stem + ".pem")
        der_path = DATA_DIR / (stem + ".der")
        run_openssl(["req", "-new", "-sha256", "-config", minimal_config(),
                     "-key", str(DATA_DIR / key_file),
                     "-subj", subject, "-out", str(pem_path)])
        run_openssl(["req", "-in", str(pem_path),
                     "-outform", "DER", "-out", str(der_path)])


def generate_certs():
    for stem, description, args, key_file in CERTS:
        pem_path = DATA_DIR / (stem + ".pem")
        der_path = DATA_DIR / (stem + ".der")
        run_openssl(["req", "-config", minimal_config()] + args +
                    ["-key", str(DATA_DIR / key_file),
                     "-out", str(pem_path)])
        run_openssl(["x509", "-in", str(pem_path),
                     "-outform", "DER", "-out", str(der_path)])


def generate_derived():
    """从既有 key_rsa_pkcs8.pem 派生 PKCS#1 公私钥与加密 PKCS#8。"""
    key_pem = DATA_DIR / "key_rsa_pkcs8.pem"
    if not key_pem.exists():
        sys.stderr.write("缺少派生材料源文件：%s\n" % key_pem)
        raise SystemExit(1)
    for stem, description, kind in DERIVED:
        pem_path = DATA_DIR / (stem + ".pem")
        der_path = DATA_DIR / (stem + ".der")
        if kind == "rsa_private":
            run_openssl(["rsa", "-in", str(key_pem), "-traditional",
                         "-out", str(pem_path)])
            run_openssl(["rsa", "-in", str(pem_path), "-traditional",
                         "-outform", "DER", "-out", str(der_path)])
        elif kind == "rsa_public":
            run_openssl(["rsa", "-in", str(key_pem), "-RSAPublicKey_out",
                         "-out", str(pem_path)])
            run_openssl(["rsa", "-pubin", "-in", str(pem_path),
                         "-RSAPublicKey_out", "-outform", "DER",
                         "-out", str(der_path)])
        elif kind == "pkcs8_encrypted":
            run_openssl(["pkcs8", "-topk8", "-in", str(key_pem),
                         "-v2", "aes-256-cbc",
                         "-passout", "pass:%s" % ENCRYPTED_PASSPHRASE,
                         "-out", str(pem_path)])
            run_openssl(["pkcs8", "-topk8", "-in", str(key_pem),
                         "-v2", "aes-256-cbc",
                         "-passout", "pass:%s" % ENCRYPTED_PASSPHRASE,
                         "-outform", "DER", "-out", str(der_path)])
        else:
            sys.stderr.write("未知派生类型：%s\n" % kind)
            raise SystemExit(1)


def generate_cms():
    """用已提交的证书/私钥生成 CMS SignedData 样本。

    签名与 signingTime 含随机/时间成分，重新生成得到的签名字节与仓库内
    已提交版本不同；测试只依赖结构字段，不依赖固定字节。
    """
    for stem in ("cert_rsa_selfsigned.pem", "key_rsa_pkcs8.pem",
                 "cert_ec_selfsigned.pem", "key_ec_pkcs8.pem"):
        if not (DATA_DIR / stem).exists():
            sys.stderr.write("缺少 CMS 材料源文件：%s\n" % (DATA_DIR / stem))
            raise SystemExit(1)

    handle, content_path = tempfile.mkstemp(prefix="asn1-cms-", suffix=".bin")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(CMS_CONTENT)
        for stem, description, signers, extra in CMS_SAMPLES:
            der_path = DATA_DIR / (stem + ".der")
            command = ["cms", "-sign", "-binary", "-md", "sha256",
                       "-in", content_path]
            for cert_file, key_file in signers:
                command += ["-signer", str(DATA_DIR / cert_file),
                            "-inkey", str(DATA_DIR / key_file)]
            command += extra + ["-outform", "DER", "-out", str(der_path)]
            run_openssl(command)
    finally:
        if os.path.exists(content_path):
            os.unlink(content_path)


def c_identifier(stem):
    """cert_rsa_selfsigned -> CertRsaSelfsigned。"""
    return "".join(part.capitalize() for part in stem.split("_"))


def write_header(der_path):
    """把 .der 转成 C 数组头；结果写入同名 .h。"""
    data = der_path.read_bytes()
    ident = c_identifier(der_path.stem)
    guard = "ASN1_TEST_DATA_%s_H_INCLUDED" % der_path.stem.upper()
    lines = []
    lines.append("/*")
    lines.append(" * Copyright (c) 2026 asn1 project contributors")
    lines.append(" * SPDX-License-Identifier: MIT")
    lines.append(" *")
    lines.append(" * 由 scripts/gen_test_data.py 自动生成，请勿手工修改。")
    lines.append(" * 源文件：tests/data/%s" % der_path.name)
    lines.append(" */")
    lines.append("#ifndef %s" % guard)
    lines.append("#define %s" % guard)
    lines.append("")
    lines.append("#include <stddef.h>")
    lines.append("")
    lines.append("#define k%sSize ((size_t)%du)" % (ident, len(data)))
    lines.append("static const unsigned char k%s[] = {" % ident)
    for offset in range(0, len(data), 12):
        chunk = data[offset:offset + 12]
        text = ", ".join("0x%02X" % byte for byte in chunk)
        lines.append("    %s," % text)
    lines.append("};")
    lines.append("")
    lines.append("#endif /* %s */" % guard)
    lines.append("")
    (der_path.with_suffix(".h")).write_text("\n".join(lines), encoding="utf-8")


def write_readme():
    readme = """# tests/data 测试材料

本目录存放零第三方 C 测试使用的真实 ASN.1 材料。所有 `.pem` / `.der` 由
`scripts/gen_test_data.py` 调用本机 `openssl` 生成；`*.h` 是同名 `.der` 的
C 数组表示，测试运行期不读文件。

## 来源与生成方式

- 生成脚本：`scripts/gen_test_data.py`（仅依赖 `openssl` 与 Python 标准库）。
- 生成命令：`python scripts/gen_test_data.py`。
- 本仓库快照使用 OpenSSL 3.5.9 生成。
- 只从已有 `.der` 重新生成头文件：`python scripts/gen_test_data.py --headers`。
- 只派生 PKCS#1 公私钥与加密 PKCS#8（不重新生成既有密钥）：
  `python scripts/gen_test_data.py --derived`。
- 只用已提交的证书/私钥生成 CMS SignedData 样本：
  `python scripts/gen_test_data.py --cms`。

| 文件 | 内容 |
| --- | --- |
| `key_rsa_pkcs8.pem/.der` | RSA-2048 私钥，PKCS#8，未加密 |
| `key_ec_pkcs8.pem/.der` | ECDSA P-256 私钥，PKCS#8，未加密 |
| `key_rsa_pss_pkcs8.pem/.der` | RSA-PSS 2048 私钥，PKCS#8，未加密 |
| `key_rsa_pkcs1_private.pem/.der` | RSA-2048 私钥，PKCS#1（传统格式） |
| `key_rsa_pkcs1_public.pem/.der` | RSA-2048 公钥，PKCS#1 `RSAPublicKey` |
| `key_rsa_pkcs8_encrypted.pem/.der` | RSA-2048 私钥，PKCS#8 `EncryptedPrivateKeyInfo`，PBES2 / AES-256-CBC，口令 `asn1-test` |
| `csr_rsa.pem/.der` | RSA-2048 证书请求（PKCS#10），SHA-256 |
| `csr_ec.pem/.der` | ECDSA P-256 证书请求（PKCS#10），SHA-256 |
| `cert_rsa_selfsigned.pem/.der` | RSA 自签名证书，SHA-256，含 basicConstraints/ SAN |
| `cert_ec_selfsigned.pem/.der` | ECDSA 自签名证书，SHA-256，含 basicConstraints/ SAN |
| `cert_rsa_pss_selfsigned.pem/.der` | RSA-PSS 自签名证书，SHA-256，AlgorithmIdentifier.parameters 为 SEQUENCE |
| `cms_rsa_attached.der` | CMS ContentInfo(SignedData)，attached，含 eContent、证书、signedAttrs |
| `cms_rsa_detached.der` | CMS ContentInfo(SignedData)，detached，无 eContent，含证书、signedAttrs |
| `cms_rsa_minimal.der` | CMS ContentInfo(SignedData) 最小样本，detached、无证书、无 signedAttrs |
| `cms_rsa_ec_multicert.der` | CMS ContentInfo(SignedData)，RSA + ECDSA 双签名者、多证书、attached |
| `cms_rsa_keyid.der` | CMS ContentInfo(SignedData)，SignerIdentifier 为 subjectKeyIdentifier |

## 重现性说明

- 密钥与签名含随机成分，重新生成得到的字节与仓库内已提交的版本**不同**；
  已提交的 `.der` / `.h` 是权威快照。
- 测试只校验“解码→编码逐字节一致”的自洽性，以及结构解析，不依赖固定字节，
  因此重新生成后重新运行测试仍然成立。
- 证书有效期从生成当天起 3650 天；测试不对具体时间做断言。
- CMS 样本的签名值（ECDSA 随机）与 signingTime 含随机/时间成分，重跑得到的
  字节与已提交快照不同；测试只读取结构字段（版本、OID、原始 TLV、计数），
  不对签名值或时间做断言。

## 变异样本

DER 严格校验的“反例”字节（非最短长度、BOOLEAN 0x01、INTEGER 前导零、
SET 乱序、时间缺秒、OID 非最短等）直接写在测试源码的字面量数组里，不进
本目录，便于就近阅读与定位。
"""
    (DATA_DIR / "README.md").write_text(readme, encoding="utf-8")


def main(argv):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    headers_only = "--headers" in argv[1:]
    derived_only = "--derived" in argv[1:]
    cms_only = "--cms" in argv[1:]

    try:
        if not headers_only and (derived_only or cms_only):
            if derived_only:
                generate_derived()
            if cms_only:
                generate_cms()
        elif not headers_only:
            generate_keys()
            generate_csrs()
            generate_certs()
            generate_derived()
            generate_cms()
    finally:
        if _CONFIG_PATH is not None and os.path.exists(_CONFIG_PATH):
            os.unlink(_CONFIG_PATH)

    der_files = sorted(DATA_DIR.glob("*.der"))
    if not der_files:
        sys.stderr.write("tests/data 下没有 .der 文件可转换\n")
        return 1
    for der_path in der_files:
        write_header(der_path)

    write_readme()
    print("已处理 %d 个 .der 文件" % len(der_files))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
