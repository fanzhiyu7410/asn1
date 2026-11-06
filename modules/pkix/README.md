# asn1-pkix

X.509 / PKIX 标准结构模块（基于 RFC 5912 扁平化 ASN.1），以 `.asn1` 描述表驱动，只依赖核心公共 C ABI。

## 用法

```c
asn1_pkix_certificate_t *cert = NULL;
asn1_err_t rc = asn1_pkix_certificate_open(ctx, pem_or_der, len, &cert);
/* 字段访问…… */
asn1_pkix_certificate_close(cert);
```

- 公共头：`asn1/pkix/pkix.h`
- 链接目标：`asn1::pkix::shared` 或 `asn1::pkix::static`（需 `find_package(asn1-pkix CONFIG REQUIRED)`）

## 描述表与缓存

**每次 `open` 加载一次 `.asn1` 描述表并构建上下文级 schema，生命周期到 `close` 结束；无全局缓存、无进程级单例。** 表数据随模块（检入产物 `generated/pkix_schema.bin`）编译进库，运行时只读；不同句柄互不共享可变状态。据此，多线程下只要每个句柄由单线程创建/使用（或在外部加锁），并发打开不同证书是安全的。

批量基准见仓库根 README 与 `docs/07-测试与验证.md`：MSVC Release 下 RSA 自签证书 1,000 次 open+close 约 445 ms，峰值堆 73,260 字节。

## 状态

0.1.0：证书打开与字段访问（RSA / RSA-PSS / EC）、ANY 三形态、独立安装消费；已在本机 MSVC、MinGW、WSL GCC/Clang、ASan/UBSan 与 ARM 交叉构建中验证，详见 `docs/06` 第 10 节。
