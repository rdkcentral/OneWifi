#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <jansson.h>

/* Forward declaration of the sanitization helper from ovsdb_sync.c.
 * When ovsdb_sync.c is compiled with -DUNIT_TEST, this symbol is exported. */
extern char* ovsdb_sanitize_json_for_logging(json_t *jsdata);

/* Test that the sanitization helper properly redacts PSK fields */
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
    json_object_set_new(auth, "type", json_string("oauth2"));
    json_object_set_new(jsdata, "auth", auth);

    /* Sanitize for logging */
    char *sanitized = ovsdb_sanitize_json_for_logging(jsdata);
    ck_assert_ptr_nonnull(sanitized);

    /* Verify sensitive token is redacted */
    ck_assert_ptr_null(strstr(sanitized, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
    ck_assert_ptr_nonnull(strstr(sanitized, "[REDACTED]"));

    /* Verify non-sensitive type is preserved */
    ck_assert_ptr_nonnull(strstr(sanitized, "oauth2"));

    free(sanitized);
    json_decref(jsdata);
}
END_TEST

/* Test that the sanitization helper redacts password fields */
START_TEST(test_ovsdb_sanitize_redacts_password)
{
    /* Create JSON with password field */
    json_t *jsdata = json_object();
    json_object_set_new(jsdata, "password", json_string("MyWPAPassword!@#"));
    json_object_set_new(jsdata, "username", json_string("admin"));

    /* Sanitize for logging */
    char *sanitized = ovsdb_sanitize_json_for_logging(jsdata);
    ck_assert_ptr_nonnull(sanitized);

    /* Verify sensitive password is redacted */
    ck_assert_ptr_null(strstr(sanitized, "MyWPAPassword!@#"));
    ck_assert_ptr_nonnull(strstr(sanitized, "[REDACTED]"));

    /* Verify non-sensitive username is preserved */
    ck_assert_ptr_nonnull(strstr(sanitized, "admin"));

    free(sanitized);
    json_decref(jsdata);
}
END_TEST

/* Test that benign JSON without sensitive fields is preserved unchanged */
START_TEST(test_ovsdb_sanitize_preserves_benign_data)
{
    /* Create JSON without any sensitive fields */
    json_t *jsdata = json_object();
    json_t *wifi = json_object();
    json_object_set_new(wifi, "ssid", json_string("PublicNetwork"));
    json_object_set_new(wifi, "channel", json_integer(6));
    json_object_set_new(wifi, "enabled", json_true());
    json_object_set_new(jsdata, "wifi", wifi);

    /* Sanitize for logging */
    char *sanitized = ovsdb_sanitize_json_for_logging(jsdata);
    ck_assert_ptr_nonnull(sanitized);

    /* Verify all non-sensitive data is preserved */
    ck_assert_ptr_nonnull(strstr(sanitized, "PublicNetwork"));
    ck_assert_ptr_nonnull(strstr(sanitized, "ssid"));
    ck_assert_ptr_nonnull(strstr(sanitized, "channel"));
    ck_assert_ptr_nonnull(strstr(sanitized, "enabled"));

    /* Verify no redaction markers appear */
    ck_assert_ptr_null(strstr(sanitized, "[REDACTED]"));

    free(sanitized);
    json_decref(jsdata);
}
END_TEST

/* Test that deeply nested sensitive fields are redacted */
START_TEST(test_ovsdb_sanitize_redacts_nested_sensitive)
{
    /* Create deeply nested JSON with sensitive fields */
    json_t *jsdata = json_object();
    json_t *level1 = json_object();
    json_t *level2 = json_object();
    json_object_set_new(level2, "secret", json_string("deeply_hidden_secret"));
    json_object_set_new(level2, "name", json_string("visible_name"));
    json_object_set_new(level1, "inner", level2);
    json_object_set_new(jsdata, "outer", level1);

    /* Sanitize for logging */
    char *sanitized = ovsdb_sanitize_json_for_logging(jsdata);
    ck_assert_ptr_nonnull(sanitized);

    /* Verify deeply nested secret is redacted */
    ck_assert_ptr_null(strstr(sanitized, "deeply_hidden_secret"));
    ck_assert_ptr_nonnull(strstr(sanitized, "[REDACTED]"));

    /* Verify non-sensitive nested data is preserved */
    ck_assert_ptr_nonnull(strstr(sanitized, "visible_name"));

    free(sanitized);
    json_decref(jsdata);
}
END_TEST

/* Test that sensitive fields inside arrays are redacted */
START_TEST(test_ovsdb_sanitize_redacts_in_arrays)
{
    /* Create JSON with sensitive fields inside an array of objects */
    json_t *jsdata = json_object();
    json_t *arr = json_array();
    json_t *item1 = json_object();
    json_object_set_new(item1, "api_key", json_string("sk-1234567890abcdef"));
    json_object_set_new(item1, "service", json_string("wifi_service"));
    json_array_append_new(arr, item1);
    json_object_set_new(jsdata, "services", arr);

    /* Sanitize for logging */
    char *sanitized = ovsdb_sanitize_json_for_logging(jsdata);
    ck_assert_ptr_nonnull(sanitized);

    /* Verify sensitive api_key is redacted */
    ck_assert_ptr_null(strstr(sanitized, "sk-1234567890abcdef"));
    ck_assert_ptr_nonnull(strstr(sanitized, "[REDACTED]"));

    /* Verify non-sensitive service name is preserved */
    ck_assert_ptr_nonnull(strstr(sanitized, "wifi_service"));

    free(sanitized);
    json_decref(jsdata);
}
END_TEST

/* Test that NULL input is handled gracefully */
START_TEST(test_ovsdb_sanitize_handles_null)
{
    char *sanitized = ovsdb_sanitize_json_for_logging(NULL);
    ck_assert_ptr_null(sanitized);
}
END_TEST

/* Test case-insensitive key matching */
START_TEST(test_ovsdb_sanitize_case_insensitive)
{
    /* Create JSON with mixed-case sensitive keys */
    json_t *jsdata = json_object();
    json_object_set_new(jsdata, "PSK", json_string("uppercase_secret"));
    json_object_set_new(jsdata, "Password", json_string("mixedcase_secret"));
    json_object_set_new(jsdata, "hostname", json_string("router.local"));

    /* Sanitize for logging */
    char *sanitized = ovsdb_sanitize_json_for_logging(jsdata);
    ck_assert_ptr_nonnull(sanitized);

    /* Verify case-insensitive redaction */
    ck_assert_ptr_null(strstr(sanitized, "uppercase_secret"));
    ck_assert_ptr_null(strstr(sanitized, "mixedcase_secret"));

    /* Verify non-sensitive data is preserved */
    ck_assert_ptr_nonnull(strstr(sanitized, "router.local"));

    free(sanitized);
    json_decref(jsdata);
}
END_TEST

/* Test that original JSON is not modified (deep copy verification) */
START_TEST(test_ovsdb_sanitize_does_not_modify_original)
{
    /* Create JSON with sensitive field */
    json_t *jsdata = json_object();
    json_object_set_new(jsdata, "psk", json_string("original_secret"));

    /* Sanitize for logging */
    char *sanitized = ovsdb_sanitize_json_for_logging(jsdata);
    ck_assert_ptr_nonnull(sanitized);
    free(sanitized);

    /* Verify original JSON still has the secret intact */
    json_t *psk_val = json_object_get(jsdata, "psk");
    ck_assert_ptr_nonnull(psk_val);
    ck_assert_str_eq(json_string_value(psk_val), "original_secret");

    json_decref(jsdata);
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_ovsdb_sanitize_redacts_psk);
    tcase_add_test(tc_core, test_ovsdb_sanitize_redacts_token);
    tcase_add_test(tc_core, test_ovsdb_sanitize_redacts_password);
    tcase_add_test(tc_core, test_ovsdb_sanitize_preserves_benign_data);
    tcase_add_test(tc_core, test_ovsdb_sanitize_redacts_nested_sensitive);
    tcase_add_test(tc_core, test_ovsdb_sanitize_redacts_in_arrays);
    tcase_add_test(tc_core, test_ovsdb_sanitize_handles_null);
    tcase_add_test(tc_core, test_ovsdb_sanitize_case_insensitive);
    tcase_add_test(tc_core, test_ovsdb_sanitize_does_not_modify_original);
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
