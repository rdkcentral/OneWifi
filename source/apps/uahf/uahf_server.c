#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "wifi_ctrl.h"
#include "wifi_hal.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#define PORT 9191
#define BUFFER_SIZE 4096

// --- URL decode helper ---
void url_decode(char *src, char *dest) {
    char a, b;
    while (*src) {
        if ((*src == '%') &&
            ((a = src[1]) && (b = src[2])) &&
            (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a') a -= 'a' - 'A';
            if (a >= 'A') a -= ('A' - 10);
            else a -= '0';
            if (b >= 'a') b -= 'a' - 'A';
            if (b >= 'A') b -= ('A' - 10);
            else b -= '0';
            *dest++ = 16 * a + b;
            src += 3;
        } else if (*src == '+') {
            *dest++ = ' ';
            src++;
        } else {
            *dest++ = *src++;
        }
    }
    *dest = '\0';
}

// --- Function to compose page dynamically ---
void send_html_page(int client_fd, int showThanks)
{
    char page[8000];

    snprintf(page, sizeof(page),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n\r\n"
        "<html>"
        "<head>"
        "<title>OneWifi Web Server</title>"
        "<style>"
        "body { background: linear-gradient(to bottom right, #4facfe, #00f2fe); "
        "       font-family: Arial; color: white; text-align:center; padding-top:50px; }"
        "h1 { font-size: 40px; text-shadow: 2px 2px #000; }"
        ".note { background: rgba(0,0,0,0.4); padding: 15px; margin: 20px auto; "
        "        width: 50%%; border-radius: 8px; font-size: 22px; color: #ffeb3b; }"
        "form { background: rgba(0,0,0,0.3); padding: 20px; display:inline-block; border-radius: 10px; }"
        "input { padding: 10px; margin: 5px; border-radius: 5px; border: none; }"
        "input[type='submit'] { background:#ff9800; color:white; cursor:pointer; }"
        "</style>"
        "</head>"
        "<body>"
        "<h1>OneWifi Web Server</h1>");

    if (showThanks) {
        strcat(page,
            "<div class='note'>Thank you for providing the details!</div>");
    }

    strcat(page,
        "<h3>Please enter your login details</h3>"
        "<form method='POST' action='/'>"
        "<input name='username' placeholder='Username'><br>"
        "<input name='password' type='password' placeholder='Password'><br>"
        "<input type='submit' value='Login'>"
        "</form>"
        "</body></html>");

    write(client_fd, page, strlen(page));
}

int uahf_start_server(wifi_app_t *app) {
    uahf_data_t *d = GET_UAHF(app); // Access your specific data
    int server_fd, client_fd;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    char buffer[BUFFER_SIZE];
    char username_local[200] = {0}, password_local[200] = {0};
    char decoded[400];

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket failed");
        exit(1);
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        exit(1);
    }

    listen(server_fd, 3);
    printf("Server running on port %d...\n", PORT);

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&addr, &addrlen);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        memset(buffer, 0, BUFFER_SIZE);
        read(client_fd, buffer, BUFFER_SIZE);

        // ---- GET Request ----
        if (strncmp(buffer, "GET", 3) == 0) {
            int showThanks = 0;

            if (strstr(buffer, "thanks=1"))
                showThanks = 1;

            send_html_page(client_fd, showThanks);
        }

        // ---- POST Request ----
        else if (strncmp(buffer, "POST", 4) == 0) {

            // Extract POST body (optional)
            char *body = strstr(buffer, "\r\n\r\n");
            if (body) body += 4;


            char *u = strstr(body, "username=");
            char *p = strstr(body, "password=");

            if (u && p) {
                sscanf(u, "username=%199[^&]", username);
                sscanf(p, "password=%199[^&]", password);

                url_decode(username, decoded);
                strcpy(username, decoded);

                url_decode(password, decoded);
                strcpy(password, decoded);

              strncpy(d->username, username_local, sizeof(d->username)-1);
              strncpy(d->password, password_local, sizeof(d->password)-1);
                printf("User submitted: %s / %s\n", username, password);
            }

            printf("POST received - redirecting with thank you note...\n");

            // Redirect to same page with thank-you flag
            const char *redirect =
                "HTTP/1.1 303 See Other\r\n"
                "Location: /?thanks=1\r\n"
                "Content-Length: 0\r\n"
                "\r\n";

            write(client_fd, redirect, strlen(redirect));

        // --- 2. EXIT LOOP CONDITION ---
        // If we successfully captured data, we break the loop 
        // so the function returns and the worker thread can finish.
            if (strlen(d->username) > 0) {
                break; 
            }
        }

        close(client_fd);
    }
/*
    char command_buffer[BUFFER_SIZE];
    int len = snprintf( command_buffer, BUFFER_SIZE, "dmcli eRT setv Device.WiFi.SSID.15.SSID string %s", username);
    if (len == 0) printf("have to use this somewhere to disable -Wall error");
    system(command_buffer);
    len = snprintf( command_buffer, BUFFER_SIZE, "dmcli eRT setv Device.WiFi.SSID.16.SSID string %s", username);
    system(command_buffer);
    len = snprintf( command_buffer, BUFFER_SIZE, "dmcli eRT setv Device.WiFi.SSID.24.SSID string %s", username);
    system(command_buffer);

    len = snprintf( command_buffer, BUFFER_SIZE,
            "dmcli eRT setv Device.WiFi.AccessPoint.15.Security.KeyPassphrase string %s", password);
    system(command_buffer);

    len = snprintf( command_buffer, BUFFER_SIZE,
            "dmcli eRT setv Device.WiFi.AccessPoint.16.Security.KeyPassphrase string %s", password);
    system(command_buffer);
    len = snprintf( command_buffer, BUFFER_SIZE,
            "dmcli eRT setv Device.WiFi.AccessPoint.24.Security.KeyPassphrase string %s", password);
    system(command_buffer);

    system("dmcli eRT setv Device.WiFi.ApplyAccessPointSettings bool true");
    */
    return 0;
}

