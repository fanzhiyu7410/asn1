# Copyright (c) 2026 asn1 project contributors
# SPDX-License-Identifier: MIT

asn1_add_test(test_version test_version.c)
target_link_libraries(test_version PRIVATE asn1_test_support)

asn1_add_test(test_context_memory test_context_memory.c)
target_link_libraries(test_context_memory PRIVATE asn1_test_support)

asn1_add_test(test_dom test_dom.c)
target_link_libraries(test_dom PRIVATE asn1_test_support)

asn1_add_test(test_schema_runtime test_schema_runtime.c)
target_link_libraries(test_schema_runtime PRIVATE asn1_test_support
                      asn1_test_schema_probe)

asn1_add_test(test_schema_table test_schema_table.c)
target_link_libraries(test_schema_table PRIVATE asn1_test_support
                      asn1_test_schema_probe asn1_test_schema_compare)

asn1_add_test(test_schema_names test_schema_names.c)
target_link_libraries(test_schema_names PRIVATE asn1_test_support)
