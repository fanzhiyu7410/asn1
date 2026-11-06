# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

asn1_add_test(test_version_conformance test_version_conformance.c)
target_link_libraries(test_version_conformance PRIVATE asn1_test_support)
