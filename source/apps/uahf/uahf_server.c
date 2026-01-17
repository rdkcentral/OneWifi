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
    wifi_util_info_print(WIFI_APPS, "UAHF: Server %d...\n", __LINE__);

    strcat(page,
        "<h3>Please enter your login details</h3>"
        "<form method='POST' action='/'>"
        "<input name='username' placeholder='Username'><br>"
        "<input name='password' type='password' placeholder='Password'><br>"
        "<input type='submit' value='Login'>"
        "</form>"
        "</body></html>");
    wifi_util_info_print(WIFI_APPS, "UAHF: Server %d...\n", __LINE__);

    write(client_fd, page, strlen(page));
    wifi_util_info_print(WIFI_APPS, "UAHF: Server %d...\n", __LINE__);

}

int uahf_start_server(wifi_app_t *app) {
    uahf_data_t *d = /*(uahf_data_t *)*/GET_UAHF(app); // Access your specific data
    int server_fd, client_fd;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    //char *buffer = NULL; // Use heap to save stack
    char decoded[200]; 
    char username_local[200] = {0};
    char password_local[200] = {0};
    wifi_util_info_print(WIFI_APPS, "UAHF: Server %d...\n", __LINE__);

    // Allocate buffer on heap to prevent stack overflow in small threads
    //buffer = (char*)malloc(BUFFER_SIZE);
       char buffer[BUFFER_SIZE];

   /* if (!buffer) {
        wifi_util_error_print(WIFI_APPS, "UAHF: OOM for buffer\n");
        return -1;
    }*/

    // --- Socket Setup ---
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        wifi_util_error_print(WIFI_APPS, "%d: UAHF: SOcket failed. .\n", __LINE__);
      //  free(buffer);
        return -1;
    }
    wifi_util_info_print(WIFI_APPS, "UAHF: Server %d...\n", __LINE__);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        wifi_util_error_print(WIFI_APPS, "UAHF: Bind failed. Check Port %d usage.\n", PORT);
        close(server_fd);
       // free(buffer);
        return -1;
    }

    listen(server_fd, 3);
    wifi_util_info_print(WIFI_APPS, "UAHF: Server started on port  %d...\n", PORT);
wifi_util_info_print(WIFI_APPS, "UAHF: strname length %d...\n", strlen(username_local));

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&addr, &addrlen);
        if (client_fd < 0) {
            wifi_util_info_print(WIFI_APPS, "UAHF: Server clientfd <0, skip loop! %d...\n", __LINE__);
            continue;
        }
        wifi_util_info_print(WIFI_APPS, "UAHF: Server %d...\n", __LINE__);

        // --- FIX: SET READ TIMEOUT ---
        // Prevents browser pre-connections (which send no data) from hanging the server
        struct timeval tv;
        tv.tv_sec = 2;  // 2 Second timeout
        tv.tv_usec = 0;
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

        memset(buffer, 0, BUFFER_SIZE);
        
        // --- FIX: CHECK READ RETURN VALUE ---
        // If bytes <= 0, it means timeout or disconnect. Don't process.
        ssize_t bytes_read = read(client_fd, buffer, BUFFER_SIZE - 1); 
   
//        read(client_fd, buffer, BUFFER_SIZE);
    wifi_util_info_print(WIFI_APPS, "UAHF: Server  read bytes %d , at line %d...\n", bytes_read, __LINE__);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0'; // Safety null terminate

        // ---- GET Request ----
        if (strncmp(buffer, "GET", 3) == 0) {
            int showThanks = 0;
            wifi_util_info_print(WIFI_APPS, "UAHF: Serving GET %d...\n", __LINE__);

            if (strstr(buffer, "thanks=1")) {
                showThanks = 1;
                wifi_util_info_print(WIFI_APPS, "UAHF: Server %d..., show thanks %d\n", __LINE__, showThanks);
            }
            send_html_page(client_fd, showThanks);
        // --- Exit Condition ---
        	if (strlen(username_local) > 0 && showThanks) {
                wifi_util_info_print(WIFI_APPS, "UAHF: Exit condition met, break from loop. Server %d...\n", __LINE__);
		        close(client_fd);
                break; 
               }
            wifi_util_info_print(WIFI_APPS, "UAHF: Server ending GET %d...\n", __LINE__);
        }
        // ---- POST Request ----
        else if (strncmp(buffer, "POST", 4) == 0) {
            wifi_util_info_print(WIFI_APPS, "UAHF: Server Handling POST %d...\n", __LINE__);

            // Extract POST body (optional)
            char *body = strstr(buffer, "\r\n\r\n");
            if (body) body += 4;


            char *u = strstr(body, "username=");
            char *p = strstr(body, "password=");
    wifi_util_info_print(WIFI_APPS, "UAHF: Server %d...\n", __LINE__);

            if (u && p) {
                sscanf(u, "username=%199[^&]", username_local);
                sscanf(p, "password=%199[^&]", password_local);
    wifi_util_info_print(WIFI_APPS, "UAHF: Server %d...\n", __LINE__);

                url_decode(username_local, decoded);
                strcpy(username_local, decoded);

                url_decode(password_local, decoded);
                strcpy(password_local, decoded);

            wifi_util_info_print(WIFI_APPS, "Captured: %s / %s\n", username_local, password_local);

            // --- CRITICAL SECTION: Save Data ---
            pthread_mutex_lock(&d->app_lock);
            strncpy(d->username, username_local, sizeof(d->username)-1);
            strncpy(d->password, password_local, sizeof(d->password)-1);
            pthread_mutex_unlock(&d->app_lock);
            wifi_util_info_print(WIFI_APPS, "Successfully updated thread struct\n");

            }

            wifi_util_info_print(WIFI_APPS, "uahf:POST received - redirecting with thank you note...\n");

            // Redirect to same page with thank-you flag
            const char *redirect =
                "HTTP/1.1 303 See Other\r\n"
                "Location: /?thanks=1\r\n"
                "Content-Length: 0\r\n"
                "\r\n";
            wifi_util_info_print(WIFI_APPS, "UAHF: Server %d...\n", __LINE__);

            write(client_fd, redirect, strlen(redirect));
        }
            } else {
            wifi_util_info_print(WIFI_APPS, "UAHF: Read timeout or empty. Dropping connection.\n");
        }
            close(client_fd);
        wifi_util_info_print(WIFI_APPS, "UAHF: Closed client_fd. Looping... %d...\n", __LINE__);
    }
    
    wifi_util_info_print(WIFI_APPS, "UAHF: Server shutdown %d...\n", __LINE__);
    close(server_fd);
   // free(buffer);

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

