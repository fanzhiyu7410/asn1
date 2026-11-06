# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT
#
# 差分测试辅助工具 asn1_dump（读 DER 文件，输出规范 TLV 树）。
# 选择 ASN1_BUILD_DIFFERENTIAL=ON 时构建；供 tests/differential/diff_asn1.py 使用，
# 不注册 CTest、不链接第三方参照工具。

if(NOT TARGET asn1::static AND NOT TARGET asn1::shared)
  return()
endif()

add_executable(asn1_dump asn1_dump.c)
if(TARGET asn1::static)
  target_link_libraries(asn1_dump PRIVATE asn1::static)
else()
  target_link_libraries(asn1_dump PRIVATE asn1::shared)
endif()
set_target_properties(asn1_dump PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON)