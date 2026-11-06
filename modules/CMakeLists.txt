# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

# 标准模块集合。每个子目录是一个独立 CMake 包，只依赖核心公共 ABI。
# 全局开关关闭时本目录不会被加入，包级开关随之失效。
if(ASN1_BUILD_MODULE_PKIX)
  add_subdirectory(pkix)
endif()
if(ASN1_BUILD_MODULE_CMS)
  add_subdirectory(cms)
endif()
if(ASN1_BUILD_MODULE_PKCS)
  add_subdirectory(pkcs)
endif()
