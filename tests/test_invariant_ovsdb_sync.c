#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

/* Test that sensitive credentials in OVSDB JSON are not logged in plaintext */
START_TEST(test_ovsdb_no_plaintext_credentials_in_logs)
{
    /* Invariant: WiFi PSK, WPA passwords, and OAuth tokens must not appear
       in plaintext in system logs when OVSDB sync operations occur */
    
    const char *payloads[] = {
        /* Exploit case: WiFi PSK in JSON */
        "{\"wifi\":{\"psk\":\"SuperSecretPassword123!\"}}",
        /* Boundary: OAuth token in JSON */
        "{\"auth\":{\"token\":\"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\"}}",
        /* Valid input: benign config without credentials */
        "{\"wifi\":{\"ssid\":\"PublicNetwork\"}}"
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);
    
    for (int i = 0; i < num_payloads; i++) {
        /* Capture stderr where wifidb_print typically logs */
        int pipe_fd[2];
        ck_assert_int_eq(pipe(pipe_fd), 0);
        
        pid_t pid = fork();
        ck_assert_int_ne(pid, -1);
        
        if (pid == 0) {
            /* Child: redirect stderr and call the vulnerable function */
            dup2(pipe_fd[1], STDERR_FILENO);
            close(pipe_fd[0]);
            close(pipe_fd[1]);
            
            /* Simulate calling ovsdb_sync with adversarial payload */
            fprintf(stderr, "Input(writing) operation to socket jsdata: %s\r\n", payloads[i]);
            exit(0);
        } else {
            /* Parent: read captured output and verify no plaintext secrets */
            close(pipe_fd[1]);
            char buffer[4096] = {0};
            ssize_t bytes = read(pipe_fd[0], buffer, sizeof(buffer) - 1);
            close(pipe_fd[0]);
            
            waitpid(pid, NULL, 0);
            
            /* Security assertion: sensitive patterns must not appear in logs */
            ck_assert_ptr_null(strstr(buffer, "SuperSecretPassword123!"));
            ck_assert_ptr_null(strstr(buffer, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
            
            /* Valid input should still be logged (no over-redaction) */
            if (i == 2) {
                ck_assert_ptr_nonnull(strstr(buffer, "PublicNetwork"));
            }
        }
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_ovsdb_no_plaintext_credentials_in_logs);
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