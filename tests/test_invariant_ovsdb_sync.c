/*
Copyright (c) 2015, Plume Design Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
   3. Neither the name of the Plume Design Inc. nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL Plume Design Inc. BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <jansson.h>

/* Include the test header which declares ovsdb_sanitize_json_for_logging when UNIT_TEST is defined */
#include "ovsdb_sync_test.h"

/* Test that sensitive credentials in OVSDB JSON are redacted by the sanitization helper */
START_TEST(test_ovsdb_sanitize_redacts_sensitive_fields)
{
    /* Invariant: WiFi PSK, WPA passwords, and OAuth tokens must not appear
       in plaintext when JSON is sanitized for logging */
    
    json_t *json_with_psk;
    json_t *json_with_token;
    json_t *json_benign;
    char *sanitized;
    
    /* Test case 1: WiFi PSK should be redacted */
    json_with_psk = json_pack("{s:{s:s, s:s}}", 
        "wifi", 
        "ssid", "TestNetwork",
        "psk", "SuperSecretTestPassword123");
    ck_assert_ptr_nonnull(json_with_psk);
    
    sanitized = ovsdb_sanitize_json_for_logging(json_with_psk);
    ck_assert_ptr_nonnull(sanitized);
    /* PSK value must not appear in sanitized output */
    ck_assert_ptr_null(strstr(sanitized, "SuperSecretTestPassword123"));
    /* REDACTED marker should be present */
    ck_assert_ptr_nonnull(strstr(sanitized, "[REDACTED]"));
    /* Non-sensitive data should still be present */
    ck_assert_ptr_nonnull(strstr(sanitized, "TestNetwork"));
    free(sanitized);
    json_decref(json_with_psk);
    
    /* Test case 2: Token should be redacted (using clearly fake token) */
    json_with_token = json_pack("{s:{s:s}}", 
        "auth", 
        "token", "test_fake_token_not_real_12345");
    ck_assert_ptr_nonnull(json_with_token);
    
    sanitized = ovsdb_sanitize_json_for_logging(json_with_token);
    ck_assert_ptr_nonnull(sanitized);
    /* Token value must not appear in sanitized output */
    ck_assert_ptr_null(strstr(sanitized, "test_fake_token_not_real_12345"));
    /* REDACTED marker should be present */
    ck_assert_ptr_nonnull(strstr(sanitized, "[REDACTED]"));
    free(sanitized);
    json_decref(json_with_token);
    
    /* Test case 3: Benign config without credentials should pass through */
    json_benign = json_pack("{s:{s:s, s:i}}", 
        "wifi", 
        "ssid", "PublicNetwork",
        "channel", 6);
    ck_assert_ptr_nonnull(json_benign);
    
    sanitized = ovsdb_sanitize_json_for_logging(json_benign);
    ck_assert_ptr_nonnull(sanitized);
    /* Non-sensitive data should be present */
    ck_assert_ptr_nonnull(strstr(sanitized, "PublicNetwork"));
    /* No redaction should occur for benign data */
    ck_assert_ptr_null(strstr(sanitized, "[REDACTED]"));
    free(sanitized);
    json_decref(json_benign);
}
END_TEST

/* Test that nested sensitive fields are also redacted */
START_TEST(test_ovsdb_sanitize_redacts_nested_sensitive_fields)
{
    json_t *nested_json;
    char *sanitized;
    
    /* Create deeply nested JSON with sensitive fields */
    nested_json = json_pack("{s:{s:{s:s, s:s}, s:s}}", 
        "config",
        "credentials",
        "password", "nested_test_password_fake",
        "api_key", "sk_test_not_a_real_key_fake123",
        "name", "TestConfig");
    ck_assert_ptr_nonnull(nested_json);
    
    sanitized = ovsdb_sanitize_json_for_logging(nested_json);
    ck_assert_ptr_nonnull(sanitized);
    
    /* Nested sensitive values must not appear */
    ck_assert_ptr_null(strstr(sanitized, "nested_test_password_fake"));
    ck_assert_ptr_null(strstr(sanitized, "sk_test_not_a_real_key_fake123"));
    /* Non-sensitive nested data should be present */
    ck_assert_ptr_nonnull(strstr(sanitized, "TestConfig"));
    
    free(sanitized);
    json_decref(nested_json);
}
END_TEST

/* Test that arrays containing objects with sensitive fields are handled */
START_TEST(test_ovsdb_sanitize_redacts_array_elements)
{
    json_t *array_json;
    char *sanitized;
    
    /* Create JSON with array containing objects with sensitive fields */
    array_json = json_pack("{s:[{s:s, s:s}, {s:s, s:s}]}", 
        "users",
        "name", "user1", "secret", "user1_fake_secret_test",
        "name", "user2", "secret", "user2_fake_secret_test");
    ck_assert_ptr_nonnull(array_json);
    
    sanitized = ovsdb_sanitize_json_for_logging(array_json);
    ck_assert_ptr_nonnull(sanitized);
    
    /* Sensitive values in array elements must not appear */
    ck_assert_ptr_null(strstr(sanitized, "user1_fake_secret_test"));
    ck_assert_ptr_null(strstr(sanitized, "user2_fake_secret_test"));
    /* Non-sensitive data should be present */
    ck_assert_ptr_nonnull(strstr(sanitized, "user1"));
    ck_assert_ptr_nonnull(strstr(sanitized, "user2"));
    
    free(sanitized);
    json_decref(array_json);
}
END_TEST

/* Test NULL input handling */
START_TEST(test_ovsdb_sanitize_handles_null)
{
    char *sanitized = ovsdb_sanitize_json_for_logging(NULL);
    ck_assert_ptr_null(sanitized);
}
END_TEST

/* Test case-insensitive key matching */
START_TEST(test_ovsdb_sanitize_case_insensitive)
{
    json_t *mixed_case_json;
    char *sanitized;
    
    /* Test various case combinations */
    mixed_case_json = json_pack("{s:s, s:s, s:s}", 
        "PASSWORD", "upper_fake_pass_test",
        "Password", "mixed_fake_pass_test",
        "TOKEN", "upper_fake_token_test");
    ck_assert_ptr_nonnull(mixed_case_json);
    
    sanitized = ovsdb_sanitize_json_for_logging(mixed_case_json);
    ck_assert_ptr_nonnull(sanitized);
    
    /* All case variations should be redacted */
    ck_assert_ptr_null(strstr(sanitized, "upper_fake_pass_test"));
    ck_assert_ptr_null(strstr(sanitized, "mixed_fake_pass_test"));
    ck_assert_ptr_null(strstr(sanitized, "upper_fake_token_test"));
    
    free(sanitized);
    json_decref(mixed_case_json);
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_ovsdb_sanitize_redacts_sensitive_fields);
    tcase_add_test(tc_core, test_ovsdb_sanitize_redacts_nested_sensitive_fields);
    tcase_add_test(tc_core, test_ovsdb_sanitize_redacts_array_elements);
    tcase_add_test(tc_core, test_ovsdb_sanitize_handles_null);
    tcase_add_test(tc_core, test_ovsdb_sanitize_case_insensitive);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
