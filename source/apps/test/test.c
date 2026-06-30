/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:
  
  Copyright 2025 RDK Management
  
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  
  http://www.apache.org/licenses/LICENSE-2.0
  
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 **************************************************************************/
#define EM_WEBSOCKET_PUSH 1

#ifdef EM_WEBSOCKET_PUSH
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <netdb.h>
#include <time.h>
#include <signal.h>
#include <stdint.h>
#include <cjson/cJSON.h>

/* Standalone logging stub — avoids pulling in the full OneWifi framework */
typedef enum { WIFI_APPS = 0 } wifi_dbg_type_t;
typedef enum { WIFI_LOG_LVL_DEBUG = 0 } wifi_log_level_t;
static void wifi_util_print(wifi_log_level_t level, wifi_dbg_type_t module,
                            const char *format, ...)
{
    va_list args;
    (void)level; (void)module;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}
#define wifi_util_dbg_print(module, format, ...) \
    wifi_util_print(WIFI_LOG_LVL_DEBUG, module, format "\n", ##__VA_ARGS__)

/* ================================================================
 * EasyMesh topology streaming over VB-SB WebSocket (wss://)
 * ================================================================ */

#define EM_TOPO_STREAM_URL_SIZE    4096
#define EM_TOPO_STREAM_TOKEN_KEY   "token="
#define EM_TOPO_STREAM_SAT_URL     "https://devprimary.vbautobot.comcast.com:6002/get_sat"
#define EM_TOPO_STREAM_TOKEN_SIZE  4096
#define EM_TOPO_GATEWAY_MAC_SIZE   18

/* Default base URL — SAT token is appended as ?token=<JWT> after fetch */
static char g_em_topo_stream_url[EM_TOPO_STREAM_URL_SIZE] =
    "wss://vb-streamer-api.vb.comcast.com:6100/ws/topology/xb";

static int                g_em_topo_socket_fd     = -1;
static SSL_CTX           *g_em_topo_ssl_ctx       = NULL;
static SSL               *g_em_topo_ssl           = NULL;
static unsigned long long g_em_topo_order_id      = 0;
static char              g_em_topo_gateway_mac[EM_TOPO_GATEWAY_MAC_SIZE] = "D4:E2:CB:9D:4E:D4";

typedef struct {
    bool     use_tls;
    char     host[128];
    uint16_t port;
    char     path_query[1024];
} em_topo_url_info_t;

/* --- URL parsing (same logic as parse_csi_stream_url in websocket.c) --- */
static bool em_topo_parse_url(em_topo_url_info_t *info)
{
    const char *url       = g_em_topo_stream_url;
    const char *scheme    = strstr(url, "://");
    const char *host_start, *host_end, *path_start;
    long parsed_port = 6100;

    if (!info) return false;
    memset(info, 0, sizeof(*info));

    if (scheme) {
        info->use_tls = ((size_t)(scheme - url) == 3 && strncmp(url, "wss", 3) == 0);
        host_start = scheme + 3;
    } else {
        info->use_tls  = true;
        host_start = url;
    }

    host_end = host_start;
    while (*host_end && *host_end != ':' && *host_end != '/' && *host_end != '?')
        host_end++;

    {
        size_t hlen = (size_t)(host_end - host_start);
        if (hlen > 0 && hlen < sizeof(info->host)) {
            memcpy(info->host, host_start, hlen);
            info->host[hlen] = '\0';
        }
    }

    if (*host_end == ':') {
        char *ep = NULL;
        long p = strtol(host_end + 1, &ep, 10);
        if (ep != host_end + 1 && p > 0 && p <= 65535) parsed_port = p;
    }
    info->port = (uint16_t)parsed_port;

    path_start = host_end;
    if (*path_start == ':')
        while (*path_start && *path_start != '/' && *path_start != '?')
            path_start++;
    snprintf(info->path_query, sizeof(info->path_query), "%s",
        *path_start ? path_start : "/");
    return (info->host[0] != '\0');
}

static int em_topo_build_url_with_token(const char *token)
{
    char updated[EM_TOPO_STREAM_URL_SIZE] = {0};
    const char *cur = g_em_topo_stream_url;
    const char *tp  = strstr(cur, EM_TOPO_STREAM_TOKEN_KEY);
    int written;

    if (!token || !token[0]) return -1;
    if (tp) {
        size_t prefix_len = (size_t)(tp - cur) + strlen(EM_TOPO_STREAM_TOKEN_KEY);
        const char *suffix = strchr(tp, '&');
        written = snprintf(updated, sizeof(updated), "%.*s%s%s",
            (int)prefix_len, cur, token, suffix ? suffix : "");
    } else {
        const char *sep = strchr(cur, '?') ? "&" : "?";
        written = snprintf(updated, sizeof(updated), "%s%s%s%s",
            cur, sep, EM_TOPO_STREAM_TOKEN_KEY, token);
    }
    if (written <= 0 || (size_t)written >= sizeof(updated)) return -1;
    snprintf(g_em_topo_stream_url, sizeof(g_em_topo_stream_url), "%s", updated);
    return 0;
}

/* --- SAT token fetch via MTLS (same pattern as fetch_latest_csi_stream_token) --- */
static int em_topo_fetch_sat_token(char *token_out, size_t token_out_len)
{
    static char password[256] = {0};
    char curl_cmd[1024] = {0};
    char curl_output[EM_TOPO_STREAM_TOKEN_SIZE] = {0};
    int  curl_exit_code = -1;
    FILE *fp = NULL;
    char line_buf[256] = {0};
    size_t used = 0;

    if (token_out == NULL || token_out_len == 0) {
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] em_topo_fetch_sat_token: invalid args (token_out=%p len=%zu)", token_out, token_out_len);
        return -1;
    }

    if (!password[0]) {
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] No cached password, running GetConfigFile /tmp/.cfgDynamicSExpki");
        if (system("GetConfigFile /tmp/.cfgDynamicSExpki") != 0) {
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] GetConfigFile failed");
            return -1;
        }
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] GetConfigFile OK, reading password");
        fp = popen("cat /tmp/.cfgDynamicSExpki", "r");
        if (fp == NULL) {
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] popen(cat /tmp/.cfgDynamicSExpki) failed");
            return -1;
        }
        if (!fgets(password, sizeof(password), fp)) {
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] fgets password failed");
            pclose(fp);
            return -1;
        }
        pclose(fp); fp = NULL;
        password[strcspn(password, "\r\n")] = '\0';
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] Password read OK (len=%zu)", strlen(password));
    } else {
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] Using cached password (len=%zu)", strlen(password));
    }

    for (int attempt = 0; attempt < 2; attempt++) {
        int status;
        const char *cert = "/nvram/certs/devicecert_2.pk12";
        snprintf(curl_cmd, sizeof(curl_cmd),
            "curl -s --cert-type P12 --cert %s:%s %s",
            cert, password, EM_TOPO_STREAM_SAT_URL);

        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] SAT attempt %d: running curl for %s", attempt + 1, EM_TOPO_STREAM_SAT_URL);
        fp = popen(curl_cmd, "r");
        if (fp == NULL) {
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] popen(curl) failed: %s", strerror(errno));
            return -1;
        }
        used = 0;
        while (fgets(line_buf, sizeof(line_buf), fp)) {
            size_t ll = strlen(line_buf);
            if (used + ll >= sizeof(curl_output) - 1) break;
            memcpy(curl_output + used, line_buf, ll); used += ll;
        }
        curl_output[used] = '\0';
        status = pclose(fp); fp = NULL;
        curl_exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] curl exit_code=%d output_len=%zu", curl_exit_code, used);

        if (curl_exit_code == 0 && used > 0) {
            while (used > 0 && (curl_output[used-1] == '\n' ||
                                curl_output[used-1] == '\r' ||
                                curl_output[used-1] == ' '))
                curl_output[--used] = '\0';
            if (used > 0 && curl_output[0] == '<') {
                wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] SAT endpoint returned HTML error page (gateway error), treating as failure");
                break;
            }
            /* Strip surrounding double quotes if the server wrapped the token */
            if (used >= 2 && curl_output[0] == '"' && curl_output[used-1] == '"') {
                memmove(curl_output, curl_output + 1, used - 2);
                used -= 2;
                curl_output[used] = '\0';
                wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] Stripped surrounding quotes from token (new len=%zu)", used);
            }
            if (used > 0 && used < token_out_len) {
                memcpy(token_out, curl_output, used + 1);
                wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] SAT token fetched OK (len=%zu)", used);
                return 0;
            }
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] curl output empty or too large (used=%zu max=%zu)", used, token_out_len);
        } else {
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] curl failed or empty response (exit_code=%d used=%zu)", curl_exit_code, used);
        }

        if (curl_exit_code == 58 && attempt == 0) {
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] PKCS12 password stale (curl error 58), refreshing and retrying");
            memset(password, 0, sizeof(password));
            if (system("GetConfigFile /tmp/.cfgDynamicSExpki") != 0) {
                wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] GetConfigFile retry failed");
                return -1;
            }
            fp = popen("cat /tmp/.cfgDynamicSExpki", "r");
            if (fp == NULL || !fgets(password, sizeof(password), fp)) {
                wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] Password retry read failed");
                if (fp) pclose(fp);
                return -1;
            }
            pclose(fp); fp = NULL;
            password[strcspn(password, "\r\n")] = '\0';
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] Password refreshed OK, retrying curl");
            continue;
        }
        break;
    }
    wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] SAT token fetch failed after all attempts");
    return -1;
}

/* --- RFC 6455 WebSocket text frame encoding (client-to-server, masked) --- */
static int ws_send_frame(const char *payload, size_t payload_len)
{
    unsigned char header[14];
    size_t header_len = 0;
    unsigned char mask[4];
    uint32_t mask_val;
    unsigned char *masked = NULL;
    int ret;

    if (!payload || payload_len == 0) return -1;

    /* Random 4-byte masking key (required for client frames per RFC 6455 §5.3) */
    mask_val = ((uint32_t)rand() << 16) ^ (uint32_t)rand();
    mask[0] = (mask_val >> 24) & 0xFF;
    mask[1] = (mask_val >> 16) & 0xFF;
    mask[2] = (mask_val >>  8) & 0xFF;
    mask[3] =  mask_val        & 0xFF;

    /* FIN=1, RSV=0, opcode=0x1 (text frame) */
    header[0] = 0x81;
    if (payload_len <= 125) {
        header[1] = 0x80 | (unsigned char)payload_len;
        header_len = 2;
    } else if (payload_len <= 65535) {
        header[1] = 0x80 | 126;
        header[2] = (unsigned char)((payload_len >> 8) & 0xFF);
        header[3] = (unsigned char)( payload_len       & 0xFF);
        header_len = 4;
    } else {
        header[1] = 0x80 | 127;
        header[2] = 0; header[3] = 0; header[4] = 0; header[5] = 0;
        header[6] = (unsigned char)((payload_len >> 24) & 0xFF);
        header[7] = (unsigned char)((payload_len >> 16) & 0xFF);
        header[8] = (unsigned char)((payload_len >>  8) & 0xFF);
        header[9] = (unsigned char)( payload_len        & 0xFF);
        header_len = 10;
    }
    /* Append masking key to header */
    header[header_len++] = mask[0];
    header[header_len++] = mask[1];
    header[header_len++] = mask[2];
    header[header_len++] = mask[3];

    /* Mask the payload */
    masked = (unsigned char *)malloc(payload_len);
    if (!masked) {
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] ws_send_frame: malloc failed (%zu bytes)", payload_len);
        return -1;
    }
    for (size_t i = 0; i < payload_len; i++)
        masked[i] = ((unsigned char)payload[i]) ^ mask[i & 3];

    /* Send header then masked payload */
    ret = g_em_topo_ssl ? SSL_write(g_em_topo_ssl, header, (int)header_len)
                        : (int)send(g_em_topo_socket_fd, header, header_len, MSG_NOSIGNAL);
    if (ret <= 0) {
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] ws_send_frame: header write failed (ret=%d)", ret);
        free(masked);
        return -1;
    }
    ret = g_em_topo_ssl ? SSL_write(g_em_topo_ssl, masked, (int)payload_len)
                        : (int)send(g_em_topo_socket_fd, masked, payload_len, MSG_NOSIGNAL);
    free(masked);
    if (ret <= 0) {
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] ws_send_frame: payload write failed (ret=%d)", ret);
        return -1;
    }
    return 0;
}

static void em_topo_close(void)
{
    wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] Closing connection (fd=%d ssl=%p)", g_em_topo_socket_fd, (void *)g_em_topo_ssl);
    if (g_em_topo_ssl) {
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] SSL_shutdown + SSL_free");
        SSL_shutdown(g_em_topo_ssl);
        SSL_free(g_em_topo_ssl);
        g_em_topo_ssl = NULL;
    }
    if (g_em_topo_ssl_ctx) {
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] SSL_CTX_free");
        SSL_CTX_free(g_em_topo_ssl_ctx);
        g_em_topo_ssl_ctx = NULL;
    }
    if (g_em_topo_socket_fd >= 0) {
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] closing socket fd=%d", g_em_topo_socket_fd);
        close(g_em_topo_socket_fd);
        g_em_topo_socket_fd = -1;
    }
    wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] Connection closed");
}

/* --- Entry point: called from publish_network_topology() --- */
static void em_topo_stream_send_topology(const char *topology_json)
{
    char          *envelope_str = NULL;
    char           ts_buf[64]   = {0};
    struct timeval tv_now       = {0};

    if (topology_json == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] topology_json is NULL, skipping");
        return;
    }

    g_em_topo_order_id++;
    gettimeofday(&tv_now, NULL);

    cJSON *envelope = cJSON_CreateObject();
    if (envelope == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] cJSON_CreateObject failed");
        return;
    }

    /* Format: {"cm_mac","ordering_id","app_type","timestamp"(mmddyyHHMMSS),"payload"(string)} */
    {
        struct tm tm_now;
        char id_buf[32] = {0};
        localtime_r(&tv_now.tv_sec, &tm_now);
        strftime(ts_buf, sizeof(ts_buf), "%m%d%y%H%M%S", &tm_now);
        snprintf(id_buf, sizeof(id_buf), "%llu", g_em_topo_order_id);
        cJSON_AddStringToObject(envelope, "cm_mac",      g_em_topo_gateway_mac);
        cJSON_AddStringToObject(envelope, "ordering_id", id_buf);
        cJSON_AddStringToObject(envelope, "app_type",    "easyMesh");
        cJSON_AddStringToObject(envelope, "timestamp",   ts_buf);
        {
            cJSON *payload_obj = cJSON_Parse(topology_json);
            if (payload_obj) {
                cJSON_AddItemToObject(envelope, "payload", payload_obj);
            } else {
                cJSON_AddStringToObject(envelope, "payload", topology_json);
            }
        }
    }

    envelope_str = cJSON_PrintUnformatted(envelope);
    cJSON_Delete(envelope);
    if (envelope_str == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] cJSON_PrintUnformatted failed");
        return;
    }

    wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] Sending topology #%llu ts=%s mac=%s", g_em_topo_order_id, ts_buf, g_em_topo_gateway_mac);

    /* ---- Connect (only if not already up) ---- */
    if (g_em_topo_socket_fd < 0) {
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] No active connection, starting connect sequence");
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] Target URL: %s", g_em_topo_stream_url);

        char token[EM_TOPO_STREAM_TOKEN_SIZE] = {0};
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] Fetching SAT token from %s", EM_TOPO_STREAM_SAT_URL);
        if (em_topo_fetch_sat_token(token, sizeof(token)) == 0) {
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] SAT token fetched OK (len=%zu)", strlen(token));
            em_topo_build_url_with_token(token);
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] URL updated with token: %s", g_em_topo_stream_url);
        } else {
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] SAT token fetch failed, proceeding without token");
        }

        em_topo_url_info_t info;
        char port_str[8] = {0};
        struct addrinfo hints = {}, *result = NULL;

        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] Parsing URL: %s", g_em_topo_stream_url);
        if (!em_topo_parse_url(&info)) {
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] URL parse failed");
            goto cleanup;
        }
        snprintf(port_str, sizeof(port_str), "%u", (unsigned int)info.port);
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] Parsed — host=%s port=%s path=%s tls=%d",
            info.host, port_str, info.path_query, info.use_tls);

        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] Resolving DNS for %s", info.host);
        hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(info.host, port_str, &hints, &result) != 0 || !result) {
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] DNS lookup failed for %s", info.host);
            goto cleanup;
        }
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] DNS resolved OK, attempting TCP connect to %s:%s", info.host, port_str);

        for (struct addrinfo *rp = result; rp; rp = rp->ai_next) {
            int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd < 0) {
                wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] socket() failed: %s", strerror(errno));
                continue;
            }
            if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
                g_em_topo_socket_fd = fd;
                break;
            }
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] connect() failed: %s", strerror(errno));
            close(fd);
        }
        freeaddrinfo(result);

        if (g_em_topo_socket_fd < 0) {
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] TCP connect to %s:%s failed", info.host, port_str);
            goto cleanup;
        }
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] TCP connected to %s:%s (fd=%d)", info.host, port_str, g_em_topo_socket_fd);

        if (info.use_tls) {
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] Starting TLS setup");
            SSL_library_init();
            g_em_topo_ssl_ctx = SSL_CTX_new(TLS_client_method());
            if (g_em_topo_ssl_ctx == NULL) {
                wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] SSL_CTX_new failed");
                em_topo_close(); goto cleanup;
            }
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] SSL_CTX created OK");

            g_em_topo_ssl = SSL_new(g_em_topo_ssl_ctx);
            if (g_em_topo_ssl == NULL) {
                wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] SSL_new failed");
                em_topo_close(); goto cleanup;
            }
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] SSL object created OK");

            SSL_set_tlsext_host_name(g_em_topo_ssl, info.host);
            SSL_set_fd(g_em_topo_ssl, g_em_topo_socket_fd);
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] Calling SSL_connect to %s", info.host);
            if (SSL_connect(g_em_topo_ssl) != 1) {
                wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] SSL_connect failed (SSL error=%d)", SSL_get_error(g_em_topo_ssl, -1));
                em_topo_close(); goto cleanup;
            }
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] TLS handshake OK — cipher=%s", SSL_get_cipher(g_em_topo_ssl));
        }

        char req[2048] = {0}, resp[1024] = {0};
        unsigned char ws_key_bytes[16];
        char ws_key_b64[25] = {0};
        RAND_bytes(ws_key_bytes, sizeof(ws_key_bytes));
        EVP_EncodeBlock((unsigned char *)ws_key_b64, ws_key_bytes, sizeof(ws_key_bytes));
        snprintf(req, sizeof(req),
            "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n",
            info.path_query, info.host, ws_key_b64);
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] Sending WS upgrade request (%zu bytes):\n%s", strlen(req), req);

        int w = g_em_topo_ssl ? SSL_write(g_em_topo_ssl, req, (int)strlen(req))
                               : (int)send(g_em_topo_socket_fd, req, strlen(req), 0);
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] WS upgrade write returned %d (expected %zu)", w, strlen(req));
        if (w <= 0) {
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] WS upgrade write failed");
            em_topo_close(); goto cleanup;
        }

        int r = g_em_topo_ssl ? SSL_read(g_em_topo_ssl, resp, (int)sizeof(resp) - 1)
                               : (int)recv(g_em_topo_socket_fd, resp, sizeof(resp) - 1, 0);
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] WS upgrade read returned %d bytes", r);
        if (r <= 0) {
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] WS upgrade read failed");
            em_topo_close(); goto cleanup;
        }
        resp[r] = '\0';
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] WS upgrade response: %.120s", resp);

        if (!strstr(resp, "101")) {
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] WS upgrade rejected — no 101 in response");
            em_topo_close(); goto cleanup;
        }
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] WS upgrade OK — connected to %s:%s%s", info.host, port_str, info.path_query);
    } else {
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] Reusing existing connection (fd=%d)", g_em_topo_socket_fd);
    }

    /* ---- Send ---- */
    {
        size_t jlen = strlen(envelope_str);
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] Sending DataFrame #%llu len=%zu", g_em_topo_order_id, jlen);
        wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] DataFrame content: %s", envelope_str);
        int n = ws_send_frame(envelope_str, jlen);
        if (n == 0) {
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] DataFrame sent successfully #%llu len=%zu", g_em_topo_order_id, jlen);
        } else {
            wifi_util_dbg_print(WIFI_APPS, "[TOPO-WS] Send failed #%llu — closing connection", g_em_topo_order_id);
            em_topo_close();
        }
    }

cleanup:
    free(envelope_str);
}

#endif /* EM_WEBSOCKET_PUSH */

#define EM_TOPO_JSON_PATH "/tmp/em_topo.json"
#define EM_TOPO_PUBLISH_INTERVAL_SECS 5

int main()
{
#ifdef EM_WEBSOCKET_PUSH
    srand((unsigned int)time(NULL));
    signal(SIGPIPE, SIG_IGN);  /* prevent crash when server closes connection mid-write */

    /* Fetch gateway MAC address (used in Python-format envelope) */
    {
        FILE *mac_fp = popen("deviceinfo.sh -cmac 2>/dev/null || "
                             "cat /sys/class/net/brlan0/address 2>/dev/null || "
                             "cat /sys/class/net/erouter0/address 2>/dev/null", "r");
        if (mac_fp) {
            if (fgets(g_em_topo_gateway_mac, sizeof(g_em_topo_gateway_mac), mac_fp))
                g_em_topo_gateway_mac[strcspn(g_em_topo_gateway_mac, "\r\n")] = '\0';
            pclose(mac_fp);
        }
        if (!g_em_topo_gateway_mac[0])
            snprintf(g_em_topo_gateway_mac, sizeof(g_em_topo_gateway_mac), "unknown");
        wifi_util_dbg_print(WIFI_APPS, "%s:%d: Gateway MAC: %s", __func__, __LINE__, g_em_topo_gateway_mac);
    }

    wifi_util_dbg_print(WIFI_APPS, "%s:%d: Starting EasyMesh topology publisher (interval=%ds file=%s)",
        __func__, __LINE__, EM_TOPO_PUBLISH_INTERVAL_SECS, EM_TOPO_JSON_PATH);

    while (1) {
        FILE *fp = fopen(EM_TOPO_JSON_PATH, "r");
        if (fp == NULL) {
            wifi_util_dbg_print(WIFI_APPS, "%s:%d: Failed to open %s: %s",
                __func__, __LINE__, EM_TOPO_JSON_PATH, strerror(errno));
        } else {
            fseek(fp, 0, SEEK_END);
            long fsize = ftell(fp);
            fseek(fp, 0, SEEK_SET);

            if (fsize <= 0) {
                wifi_util_dbg_print(WIFI_APPS, "%s:%d: %s is empty, skipping",
                    __func__, __LINE__, EM_TOPO_JSON_PATH);
                fclose(fp);
            } else {
                char *json_buf = (char *)malloc((size_t)fsize + 1);
                if (json_buf == NULL) {
                    wifi_util_dbg_print(WIFI_APPS, "%s:%d: malloc failed for %ld bytes",
                        __func__, __LINE__, fsize);
                    fclose(fp);
                } else {
                    size_t nread = fread(json_buf, 1, (size_t)fsize, fp);
                    fclose(fp);
                    json_buf[nread] = '\0';

                    wifi_util_dbg_print(WIFI_APPS, "%s:%d: Publishing topology from %s (%zu bytes)",
                        __func__, __LINE__, EM_TOPO_JSON_PATH, nread);
                    em_topo_stream_send_topology(json_buf);
                    free(json_buf);
                }
            }
        }

        sleep(EM_TOPO_PUBLISH_INTERVAL_SECS);
    }
#endif
    return 0;
}