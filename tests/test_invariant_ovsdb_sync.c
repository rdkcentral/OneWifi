#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <jansson.h>

/* Forward declaration of the sanitization helper from ovsdb_sync.c */
extern char* ovsdb_sanitize_json_for_logging(json_t *jsdata);

/* Test that the sanitization helper properly redacts sensitive fields */
START_TEST(test_ovsdb_sanitize_redacts_psk)
{
    /* Create JSON with PSK field */
    json_t *jsdata = json_object();
    json_t *wifi = json_object();
    json_object_set_new(wifi, "psk", json_string("SuperSecretPassword123!"));
    json_object_set_new(wifi, "ssid", json_string("PublicNetwork"));
    json_object_set_new(jsdata, "wifi", wifi);
    
    /* Sanitize for logging */
    char *sanitized = ovsdb_sanitize_json_for_logging(jsdata);
    ck_assert_ptr_nonnull(sanitized);
    
    /* Verify sensitive PSK is redacted */
    ck_assert_ptr_null(strstr(sanitized, "SuperSecretPassword123!"));
    ck_assert_ptr_nonnull(strstr(sanitized, "[REDACTED]"));
    
    /* Verify non-sensitive SSID is preserved */
    ck_assert_ptr_nonnull(strstr(sanitized, "PublicNetwork"));
    
    free(sanitized);
    json_decref(jsdata);
}
END_TEST

/* Test that the sanitization helper redacts OAuth tokens */
START_TEST(test_ovsdb_sanitize_redacts_token)
{
    /* Create JSON with OAuth token */
    json_t *jsdata = json_object();
    json_t *auth = json_object();
    json_object_set_new(auth, "token", json_string("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
    json_object_set_new(jsdata, "auth", auth);
    
    /* Sanitize for logging */
    char *sanitized = ovsdb_sanitize_json_for_logging(jsdata);
    ck_assert_ptr_nonnull(sanitized);
    
    /* Verify sensitive token is redacted */
    ck_assert_ptr_null(strstr(sanitized, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
    ck_assert_ptr_nonnull(strstr(sanitized, "[REDACTED]"));
    
    free(sanitized);
    json_decref(jsdata);
}
END_TEST

/* Test that the sanitization helper preserves benign data */
START_TEST(test_ovsdb_sanitize_preserves_benign_data)
{
    /* Create JSON with only benign fields */
    json_t *jsdata = json_object();
    json_t *wifi = json_object();
    json_object_set_new(wifi, "ssid", json_string("PublicNetwork"));
    json_object_set_new(wifi, "channel", json_integer(6));
    json_object_set_new(jsdata, "wifi", wifi);
    
    /* Sanitize for logging */
    char *sanitized = ovsdb_sanitize_json_for_logging(jsdata);
    ck_assert_ptr_nonnull(sanitized);
    
    /* Verify benign data is preserved */
    ck_assert_ptr_nonnull(strstr(sanitized, "PublicNetwork"));
    ck_assert_ptr_nonnull(strstr(sanitized, "6"));
    
    /* Verify no redaction markers for benign data */
    ck_assert_ptr_null(strstr(sanitized, "[REDACTED]"));
    
    free(sanitized);
    json_decref(jsdata);
}
END_TEST

/* Test that the sanitization helper handles nested structures */
START_TEST(test_ovsdb_sanitize_handles_nested_structures)
{
    /* Create nested JSON with sensitive fields at multiple levels */
    json_t *jsdata = json_object();
    json_t *wifi = json_object();
    json_t *security = json_object();
    
    json_object_set_new(security, "password", json_string("SecretPass123!"));
    json_object_set_new(security, "method", json_string("WPA2"));
    json_object_set_new(wifi, "security", security);
    json_object_set_new(wifi, "ssid", json_string("MyNetwork"));
    json_object_set_new(jsdata, "wifi", wifi);
    
    /* Sanitize for logging */
    char *sanitized = ovsdb_sanitize_json_for_logging(jsdata);
    ck_assert_ptr_nonnull(sanitized);
    
    /* Verify nested sensitive password is redacted */
    ck_assert_ptr_null(strstr(sanitized, "SecretPass123!"));
    ck_assert_ptr_nonnull(strstr(sanitized, "[REDACTED]"));
    
    /* Verify non-sensitive nested fields are preserved */
    ck_assert_ptr_nonnull(strstr(sanitized, "WPA2"));
    ck_assert_ptr_nonnull(strstr(sanitized, "MyNetwork"));
    
    free(sanitized);
    json_decref(jsdata);
}
END_TEST

/* Test that the sanitization helper handles NULL input */
START_TEST(test_ovsdb_sanitize_handles_null_input)
{
    /* Call with NULL should return NULL */
    char *sanitized = ovsdb_sanitize_json_for_logging(NULL);
    ck_assert_ptr_null(sanitized);
}
END_TEST

/* Test that the sanitization helper handles arrays with sensitive data */
START_TEST(test_ovsdb_sanitize_handles_arrays)
{
    /* Create JSON with array containing objects with sensitive fields */
    json_t *jsdata = json_object();
    json_t *networks = json_array();
    
    json_t *net1 = json_object();
    json_object_set_new(net1, "ssid", json_string("Network1"));
    json_object_set_new(net1, "psk", json_string("Secret1"));
    json_array_append_new(networks, net1);
    
    json_t *net2 = json_object();
    json_object_set_new(net2, "ssid", json_string("Network2"));
    json_object_set_new(net2, "psk", json_string("Secret2"));
    json_array_append_new(networks, net2);
    
    json_object_set_new(jsdata, "networks", networks);
    
    /* Sanitize for logging */
    char *sanitized = ovsdb_sanitize_json_for_logging(jsdata);
    ck_assert_ptr_nonnull(sanitized);
    
    /* Verify sensitive PSKs are redacted */
    ck_assert_ptr_null(strstr(sanitized, "Secret1"));
    ck_assert_ptr_null(strstr(sanitized, "Secret2"));
    
    /* Verify non-sensitive SSIDs are preserved */
    ck_assert_ptr_nonnull(strstr(sanitized, "Network1"));
    ck_assert_ptr_nonnull(strstr(sanitized, "Network2"));
    
    free(sanitized);
    json_decref(jsdata);
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("OVSDB Sanitization");

    tcase_add_test(tc_core, test_ovsdb_sanitize_redacts_psk);
    tcase_add_test(tc_core, test_ovsdb_sanitize_redacts_token);
    tcase_add_test(tc_core, test_ovsdb_sanitize_preserves_benign_data);
    tcase_add_test(tc_core, test_ovsdb_sanitize_handles_nested_structures);
    tcase_add_test(tc_core, test_ovsdb_sanitize_handles_null_input);
    tcase_add_test(tc_core, test_ovsdb_sanitize_handles_arrays);
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
