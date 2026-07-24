/**
 * ws_client.cpp — Generic WebSocket client library (C++11 implementation)
 *
 * C++ features used:
 *   - PIMPL (WsClient::Impl) for ABI stability
 *   - RAII: SocketFd class, std::unique_ptr<SSL/SSL_CTX> with custom deleters
 *   - std::thread + std::atomic<bool> for the recv thread
 *   - std::recursive_mutex + std::lock_guard / std::unique_lock
 *   - std::condition_variable for ack synchronisation
 *   - UrlInfo / WsFrame structs with bool valid flag (replaces std::optional)
 *   - std::vector<uint8_t> for frame payloads (automatic memory management)
 *   - std::string / const std::string& throughout (replaces std::string_view)
 *   - std::chrono for timeouts
 *   - std::function for the recv callback
 *   - enum class WsOpcode for type-safe opcode dispatch
 */

#include "ws_client.h"
#include "wifi_util.h"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

/* ── Logging (backed by wifi_util_print / WIFI_WS module) ────────────────── */
#define WS_ERR(impl, fmt, ...)  \
    wifi_util_error_print(WIFI_WS, "[ws:%s] %s:%d " fmt, \
                          (impl).name.c_str(), __func__, __LINE__, ##__VA_ARGS__)
#define WS_INFO(impl, fmt, ...) \
    wifi_util_info_print(WIFI_WS,  "[ws:%s] %s:%d " fmt, \
                         (impl).name.c_str(), __func__, __LINE__, ##__VA_ARGS__)
#define WS_DBG(impl, fmt, ...)  \
    wifi_util_dbg_print(WIFI_WS,   "[ws:%s] %s:%d " fmt, \
                        (impl).name.c_str(), __func__, __LINE__, ##__VA_ARGS__)

/* ── Internal constants ──────────────────────────────────────────────────── */
static constexpr std::size_t kAckBufSize        = 512;
static constexpr std::size_t kHandshakeBufSize  = 4096;
static constexpr std::size_t kMaxControlPayload = 125;   // RFC 6455 §5.5
static constexpr std::size_t kMaxFramePayload   = 1024 * 1024; // defensive cap for inbound frames
static constexpr uint16_t    kDefaultPortWs     = 80;
static constexpr uint16_t    kDefaultPortWss    = 443;

/* ══════════════════════════════════════════════════════════════════════════
 * RAII wrappers
 * ══════════════════════════════════════════════════════════════════════════ */

/**
 * RAII wrapper for a POSIX socket file descriptor.
 * Calls close() on destruction; movable but not copyable.
 */
class SocketFd {
public:
    SocketFd() noexcept = default;
    explicit SocketFd(int fd) noexcept : fd_(fd) {}
    ~SocketFd() { reset(); }

    SocketFd(const SocketFd&)            = delete;
    SocketFd& operator=(const SocketFd&) = delete;

    SocketFd(SocketFd&& o) noexcept : fd_(o.release()) {}
    SocketFd& operator=(SocketFd&& o) noexcept {
        if (this != &o) { reset(); fd_ = o.release(); }
        return *this;
    }

    int  get()   const noexcept { return fd_; }
    bool valid() const noexcept { return fd_ >= 0; }

    int release() noexcept { int f = fd_; fd_ = -1; return f; }

    void reset(int fd = -1) noexcept {
        if (fd_ >= 0) ::close(fd_);
        fd_ = fd;
    }

    /** Interrupt a blocking recv() by shutting both directions. */
    void shutdown_rw() noexcept {
        if (fd_ >= 0) ::shutdown(fd_, SHUT_RDWR);
    }

private:
    int fd_ = -1;
};

/* Custom deleters for OpenSSL handles */
struct SslDeleter    { void operator()(SSL     *p) const noexcept { SSL_shutdown(p); SSL_free(p); } };
struct SslCtxDeleter { void operator()(SSL_CTX *p) const noexcept { SSL_CTX_free(p); } };

using SslPtr    = std::unique_ptr<SSL,     SslDeleter>;
using SslCtxPtr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;

/* ══════════════════════════════════════════════════════════════════════════
 * URL parser
 * ══════════════════════════════════════════════════════════════════════════ */

struct UrlInfo {
    bool        valid     = false;
    bool        use_tls   = true;
    std::string host;
    uint16_t    port      = 0;
    std::string path_query;

    /** Parse ws[s]://host[:port]/path[?query].  Returns UrlInfo with valid=false on error. */
    static UrlInfo parse(const std::string& url)
    {
        UrlInfo info;
        std::size_t pos = 0;

        if (url.substr(pos, 6) == "wss://") {
            info.use_tls = true;  pos += 6;
        } else if (url.substr(pos, 5) == "ws://") {
            info.use_tls = false; pos += 5;
        } else {
            // Reject explicit non-websocket schemes (e.g. https://...).
            if (url.find("://") != std::string::npos)
                return info;
            // Keep supporting scheme-less host/path by defaulting to TLS.
            info.use_tls = true;
        }

        // Host (ends at ':', '/', '?', or end)
        std::size_t host_end = url.find_first_of(":/?\0", pos);
        info.host = url.substr(pos, host_end == std::string::npos
                                    ? std::string::npos : host_end - pos);
        if (info.host.empty()) return info;  // valid stays false
        pos += info.host.size();

        // Optional port
        long parsed_port = -1;
        if (pos < url.size() && url[pos] == ':') {
            ++pos;
            std::size_t pend = url.find_first_of("/?\0", pos);
            std::string port_str = url.substr(pos, pend == std::string::npos
                                                    ? std::string::npos : pend - pos);
            char *ep = nullptr;
            parsed_port = std::strtol(port_str.c_str(), &ep, 10);
            if (*ep != '\0' || parsed_port <= 0 || parsed_port > 65535)
                parsed_port = -1;
            pos += port_str.size();
        }

        info.port = (parsed_port > 0)
                    ? static_cast<uint16_t>(parsed_port)
                    : (info.use_tls ? kDefaultPortWss : kDefaultPortWs);

        info.path_query = (pos < url.size()) ? url.substr(pos) : "/";
        info.valid = true;
        return info;
    }
};

/* ══════════════════════════════════════════════════════════════════════════
 * WsClient::Impl — all mutable state lives here (PIMPL)
 * ══════════════════════════════════════════════════════════════════════════ */

struct WsClient::Impl {
    /* Config */
    std::string          name;
    bool                 verify_peer;
    std::chrono::seconds ack_timeout;

    /* Connection state — serialised by mtx (recursive for lock()/unlock()) */
    mutable std::recursive_mutex mtx;
    SocketFd   socket;
    SslCtxPtr  ssl_ctx;
    SslPtr     ssl;
    std::string url;

    /* Recv thread */
    std::thread       recv_thread;
    std::atomic<bool> recv_running{false};

    /* Server-ack slot (separate mutex so wait_for_ack doesn't hold main lock) */
    std::mutex              ack_mtx;
    std::condition_variable ack_cv;
    std::string             ack_resp;
    bool                    ack_ready = false;
    bool                    ack_user_disabled = false;

    /* User recv callback */
    std::mutex       cb_mtx;
    WsClient::RecvCb recv_cb;

    explicit Impl(WsClient::Config cfg)
        : name(std::move(cfg.name))
        , verify_peer(cfg.verify_peer)
        , ack_timeout(cfg.ack_timeout)
    {}
};

/* ══════════════════════════════════════════════════════════════════════════
 * Internal I/O helpers
 * ══════════════════════════════════════════════════════════════════════════ */

static int impl_read(WsClient::Impl& impl, char *buf, std::size_t len)
{
    if (impl.ssl)
        return SSL_read(impl.ssl.get(), buf, static_cast<int>(len));
    return static_cast<int>(::recv(impl.socket.get(), buf, len, 0));
}

static bool impl_read_exact(WsClient::Impl& impl, uint8_t *buf, std::size_t len)
{
    std::size_t done = 0;
    while (done < len) {
        int n = impl_read(impl, reinterpret_cast<char*>(buf) + done, len - done);
        if (n <= 0) return false;
        done += static_cast<std::size_t>(n);
    }
    return true;
}

/** SSL_write with SIGPIPE blocked to avoid crashing on a broken connection. */
static int ssl_write_nosigpipe(SSL *ssl, const uint8_t *buf, int len)
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    (void)pthread_sigmask(SIG_BLOCK, &set, nullptr);
    return SSL_write(ssl, buf, len);
}

static bool impl_send_all(WsClient::Impl& impl, const uint8_t *buf, std::size_t len)
{
#ifdef MSG_NOSIGNAL
    constexpr int kSendFlags = MSG_NOSIGNAL;
#else
    constexpr int kSendFlags = 0;
#endif
    std::size_t sent = 0;
    while (sent < len) {
        int n = impl.ssl
            ? ssl_write_nosigpipe(impl.ssl.get(), buf + sent,
                                  static_cast<int>(len - sent))
            : static_cast<int>(::send(impl.socket.get(), buf + sent,
                                      len - sent, kSendFlags));
        if (n <= 0) {
            WS_ERR(impl, "send failed n:%d errno:%d(%s)\n",
                   n, errno, strerror(errno));
            return false;
        }
        sent += static_cast<std::size_t>(n);
    }
    return true;
}

/* ══════════════════════════════════════════════════════════════════════════
 * RFC 6455 frame builders  (caller holds impl.mtx)
 * ══════════════════════════════════════════════════════════════════════════ */

/** Apply per-RFC-6455 client-side masking to payload. */
static std::vector<uint8_t> apply_mask(const uint8_t *payload, std::size_t len,
                                        const uint8_t mask[4])
{
    std::vector<uint8_t> out(len);
    for (std::size_t i = 0; i < len; ++i)
        out[i] = payload[i] ^ mask[i % 4];
    return out;
}

/** Send a masked control frame (Ping / Pong / Close).  Caller holds impl.mtx. */
static bool send_control_frame(WsClient::Impl& impl, WsOpcode opcode,
                                const uint8_t *payload, std::size_t payload_len)
{
    auto raw_op = static_cast<uint8_t>(opcode);
    if ((raw_op & 0xF0u) != 0 || payload_len > kMaxControlPayload) return false;

    uint8_t header[6];
    header[0] = static_cast<uint8_t>(0x80u | raw_op);
    header[1] = static_cast<uint8_t>(0x80u | payload_len);

    uint8_t mask[4];
    if (RAND_bytes(mask, sizeof(mask)) != 1) return false;
    std::memcpy(header + 2, mask, sizeof(mask));

    if (!impl_send_all(impl, header, sizeof(header))) return false;
    if (payload_len > 0) {
        auto masked = apply_mask(payload, payload_len, mask);
        if (!impl_send_all(impl, masked.data(), payload_len)) return false;
    }
    return true;
}

/** Send a masked data frame (Text / Binary).  Caller holds impl.mtx. */
static bool send_data_frame(WsClient::Impl& impl, WsOpcode opcode,
                             const uint8_t *payload, std::size_t payload_len)
{
    uint8_t header[14];
    std::size_t header_len;
    header[0] = static_cast<uint8_t>(0x80u | static_cast<uint8_t>(opcode));

    if (payload_len <= 125) {
        header[1] = static_cast<uint8_t>(0x80u | payload_len);
        header_len = 2;
    } else if (payload_len <= 65535) {
        header[1] = static_cast<uint8_t>(0x80u | 126u);
        header[2] = static_cast<uint8_t>((payload_len >> 8) & 0xFFu);
        header[3] = static_cast<uint8_t>(payload_len & 0xFFu);
        header_len = 4;
    } else {
        const uint64_t payload_len_u64 = static_cast<uint64_t>(payload_len);
        header[1] = static_cast<uint8_t>(0x80u | 127u);
        for (int i = 0; i < 8; ++i) {
            header[2 + i] = static_cast<uint8_t>(
                (payload_len_u64 >> (56 - (8 * i))) & 0xFFu);
        }
        header_len = 10;
    }

    uint8_t mask[4];
    if (RAND_bytes(mask, sizeof(mask)) != 1) return false;
    std::memcpy(header + header_len, mask, sizeof(mask));
    header_len += sizeof(mask);

    if (!impl_send_all(impl, header, header_len)) return false;
    if (payload_len > 0 && payload) {
        auto masked = apply_mask(payload, payload_len, mask);
        if (!impl_send_all(impl, masked.data(), payload_len)) return false;
    }
    return true;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Ack-slot helpers
 * ══════════════════════════════════════════════════════════════════════════ */

static void notify_ack_waiters(WsClient::Impl& impl, const char *reason)
{
    std::lock_guard<std::mutex> lk(impl.ack_mtx);
    impl.ack_resp  = reason ? reason : "CONNECTION_CLOSED";
    impl.ack_ready = true;
    impl.ack_cv.notify_all();
}

/* ══════════════════════════════════════════════════════════════════════════
 * WebSocket HTTP upgrade handshake
 * ══════════════════════════════════════════════════════════════════════════ */

static bool do_ws_handshake(WsClient::Impl& impl, const UrlInfo& info)
{
    uint8_t nonce[16];
    if (RAND_bytes(nonce, static_cast<int>(sizeof(nonce))) != 1) return false;

    char ws_key_b64[32]{};
    EVP_EncodeBlock(reinterpret_cast<uint8_t*>(ws_key_b64),
                    nonce, static_cast<int>(sizeof(nonce)));

    // Build the HTTP upgrade request
    char req[kHandshakeBufSize];
    std::snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%u\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n",
        info.path_query.c_str(), info.host.c_str(),
        static_cast<unsigned>(info.port), ws_key_b64);

    if (!impl_send_all(impl, reinterpret_cast<const uint8_t*>(req),
                       std::strlen(req))) return false;

    // Read response headers
    std::string resp;
    resp.reserve(1024);
    while (resp.find("\r\n\r\n") == std::string::npos) {
        char tmp[256];
        int n = impl_read(impl, tmp, sizeof(tmp) - 1);
        if (n <= 0) return false;
        resp.append(tmp, static_cast<std::size_t>(n));
        if (resp.size() > kHandshakeBufSize) return false;
    }

    if (resp.find(" 101 ") == std::string::npos) {
        WS_ERR(impl, "handshake rejected: %.120s\n", resp.c_str());
        return false;
    }

    // Verify Sec-WebSocket-Accept (RFC 6455 §4.1)
    {
        static constexpr const char *kMagic =
            "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        std::string inbuf = std::string(ws_key_b64) + kMagic;
        uint8_t digest[SHA_DIGEST_LENGTH];
        SHA1(reinterpret_cast<const uint8_t*>(inbuf.c_str()),
             inbuf.size(), digest);
        char expected_b64[32]{};
        EVP_EncodeBlock(reinterpret_cast<uint8_t*>(expected_b64),
                        digest, SHA_DIGEST_LENGTH);

        if (resp.find("Sec-WebSocket-Accept:") == std::string::npos ||
            resp.find(expected_b64) == std::string::npos) {
            WS_ERR(impl, "Sec-WebSocket-Accept mismatch\n");
            return false;
        }
    }

    WS_INFO(impl, "WebSocket handshake OK host:%s port:%u path:%s tls:%d\n",
            info.host.c_str(), static_cast<unsigned>(info.port),
            info.path_query.c_str(), static_cast<int>(info.use_tls));
    return true;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Connection lifecycle helpers  (caller holds impl.mtx)
 * ══════════════════════════════════════════════════════════════════════════ */

/** Release SSL and socket resources.  Does NOT join the recv thread. */
static void close_connection(WsClient::Impl& impl)
{
    impl.ssl.reset();
    impl.ssl_ctx.reset();
    impl.socket.reset();
}

/** TCP + optional TLS + WebSocket handshake. Caller holds impl.mtx. */
static int connect_locked(WsClient::Impl& impl)
{
    if (impl.socket.valid()) return 0;  // already connected

    UrlInfo info = UrlInfo::parse(impl.url);
    if (!info.valid) {
        WS_ERR(impl, "failed to parse URL: %s\n", impl.url.c_str());
        return -1;
    }

    // DNS + TCP
    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo *raw_ai = nullptr;
    int rc = ::getaddrinfo(info.host.c_str(),
                           std::to_string(info.port).c_str(),
                           &hints, &raw_ai);
    if (rc != 0) {
        WS_ERR(impl, "getaddrinfo failed: %s\n", gai_strerror(rc));
        return -1;
    }
    auto ai_guard = std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)>(
        raw_ai, ::freeaddrinfo);

    for (addrinfo *rp = raw_ai; rp != nullptr; rp = rp->ai_next) {
        SocketFd fd(::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol));
        if (!fd.valid()) continue;
        if (::connect(fd.get(), rp->ai_addr, rp->ai_addrlen) == 0) {
            impl.socket = std::move(fd);
            break;
        }
    }

    if (!impl.socket.valid()) {
        WS_ERR(impl, "TCP connect failed to %s:%u\n",
               info.host.c_str(), static_cast<unsigned>(info.port));
        return -1;
    }

    // TLS layer
    if (info.use_tls) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        SSL_library_init();
        SSL_load_error_strings();
#endif
        impl.ssl_ctx.reset(SSL_CTX_new(TLS_client_method()));
        if (!impl.ssl_ctx) { impl.socket.reset(); return -1; }

        if (!impl.verify_peer)
            SSL_CTX_set_verify(impl.ssl_ctx.get(), SSL_VERIFY_NONE, nullptr);

        impl.ssl.reset(SSL_new(impl.ssl_ctx.get()));
        if (!impl.ssl) { close_connection(impl); return -1; }

        SSL_set_tlsext_host_name(impl.ssl.get(), info.host.c_str());
        SSL_set_fd(impl.ssl.get(), impl.socket.get());

        if (SSL_connect(impl.ssl.get()) != 1) {
            WS_ERR(impl, "SSL_connect failed\n");
            close_connection(impl); return -1;
        }
    }

    // WebSocket upgrade
    if (!do_ws_handshake(impl, info)) {
        close_connection(impl); return -1;
    }

    // Clear any stale ack state from a previous session
    {
        std::lock_guard<std::mutex> lk(impl.ack_mtx);
        impl.ack_ready = false;
        impl.ack_resp.clear();
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Recv frame reader
 * ══════════════════════════════════════════════════════════════════════════ */

struct WsFrame {
    bool                 valid   = false;
    WsOpcode             opcode  = WsOpcode::Continuation;
    bool                 fin     = false;
    std::vector<uint8_t> payload;
};

/**
 * Read one complete WebSocket frame from the server.
 * Does NOT hold impl.mtx (called from the recv thread while blocked on I/O).
 */
static WsFrame recv_frame(WsClient::Impl& impl)
{
    uint8_t hdr[2];
    if (!impl_read_exact(impl, hdr, 2)) return WsFrame{};

    if (hdr[0] & 0x70u) {  // RSV bits must be 0
        WS_ERR(impl, "RSV bits set (0x%02x)\n", hdr[0] & 0x70u);
        return WsFrame{};
    }

    WsFrame frame;
    frame.fin    = (hdr[0] & 0x80u) != 0;
    frame.opcode = static_cast<WsOpcode>(hdr[0] & 0x0Fu);
    bool    is_masked   = (hdr[1] & 0x80u) != 0;
    std::size_t len     = hdr[1] & 0x7Fu;

    // Extended length
    if (len == 126) {
        uint8_t ext[2];
        if (!impl_read_exact(impl, ext, 2)) return WsFrame{};
        len = (static_cast<std::size_t>(ext[0]) << 8) | ext[1];
    } else if (len == 127) {
        uint8_t ext[8];
        if (!impl_read_exact(impl, ext, 8)) return WsFrame{};
        if (ext[0] | ext[1] | ext[2] | ext[3]) return WsFrame{}; // > 4 GiB
        len = (static_cast<std::size_t>(ext[4]) << 24) |
              (static_cast<std::size_t>(ext[5]) << 16) |
              (static_cast<std::size_t>(ext[6]) <<  8) |
               static_cast<std::size_t>(ext[7]);
    }

    uint8_t mask_key[4] = {};
    if (is_masked && !impl_read_exact(impl, mask_key, 4)) return WsFrame{};

    if (len > kMaxFramePayload) {
        WS_ERR(impl, "frame too large len:%zu max:%zu\n", len, kMaxFramePayload);
        return WsFrame{};
    }

    frame.payload.resize(len);
    if (len > 0) {
        if (!impl_read_exact(impl, frame.payload.data(), len)) return WsFrame{};
        if (is_masked) {
            for (std::size_t i = 0; i < len; ++i)
                frame.payload[i] ^= mask_key[i % 4];
        }
    }
    frame.valid = true;
    return frame;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Background recv / ping-pong thread
 * ══════════════════════════════════════════════════════════════════════════ */

static void recv_thread_fn(WsClient::Impl *impl)
{
    WS_INFO(*impl, "recv thread started\n");

    bool keep_running = true;
    while (keep_running && impl->recv_running.load(std::memory_order_relaxed)) {

        // Blocking frame read — does NOT hold impl->mtx
        WsFrame frame = recv_frame(*impl);

        if (!frame.valid) {
            if (!impl->recv_running.load(std::memory_order_relaxed)) {
                WS_INFO(*impl, "recv thread: read interrupted by shutdown\n");
            } else {
                WS_ERR(*impl, "recv thread: read error — closing connection\n");
                std::lock_guard<std::recursive_mutex> lk(impl->mtx);
                impl->recv_running = false;
                close_connection(*impl);
                notify_ack_waiters(*impl, nullptr);
            }
            break;
        }

        WS_DBG(*impl, "recv opcode=0x%x fin=%d len=%zu\n",
               static_cast<uint8_t>(frame.opcode),
               static_cast<int>(frame.fin),
               frame.payload.size());

        // Validate control frames: must have FIN, payload <= 125 bytes
        if ((static_cast<uint8_t>(frame.opcode) & 0x08u) &&
            (!frame.fin || frame.payload.size() > kMaxControlPayload)) {
            WS_ERR(*impl, "invalid control frame opcode=0x%x\n",
                   static_cast<uint8_t>(frame.opcode));
            std::lock_guard<std::recursive_mutex> lk(impl->mtx);
            impl->recv_running = false;
            close_connection(*impl);
            notify_ack_waiters(*impl, nullptr);
            break;
        }

        switch (frame.opcode) {

        case WsOpcode::Ping: {
            WS_INFO(*impl, "PING len=%zu — sending PONG\n", frame.payload.size());
            std::lock_guard<std::recursive_mutex> lk(impl->mtx);
            if (impl->socket.valid()) {
                if (send_control_frame(*impl, WsOpcode::Pong,
                                       frame.payload.data(),
                                       frame.payload.size()))
                    WS_INFO(*impl, "PONG sent len=%zu\n", frame.payload.size());
                else
                    WS_ERR(*impl, "failed to send PONG\n");
            }
            break;
        }

        case WsOpcode::Close: {
            WS_INFO(*impl, "CLOSE frame len=%zu — echoing\n", frame.payload.size());
            std::lock_guard<std::recursive_mutex> lk(impl->mtx);
            if (impl->socket.valid())
                send_control_frame(*impl, WsOpcode::Close,
                                   frame.payload.data(), frame.payload.size());
            impl->recv_running = false;
            close_connection(*impl);
            notify_ack_waiters(*impl, nullptr);
            keep_running = false;
            break;
        }

        case WsOpcode::Text:
        case WsOpcode::Binary: {
            // Build string for logging and ack matching
            std::string text(reinterpret_cast<const char*>(frame.payload.data()),
                             frame.payload.size());
            WS_INFO(*impl, "data opcode=0x%x len=%zu: %.256s\n",
                    static_cast<uint8_t>(frame.opcode),
                    frame.payload.size(), std::string(text).c_str());

            // 1. Deposit in ack slot (signal waiting send paths)
            {
                std::lock_guard<std::mutex> lk(impl->ack_mtx);
                impl->ack_resp  = text.substr(0, kAckBufSize - 1);
                impl->ack_ready = true;
                impl->ack_cv.notify_one();
            }

            // 2. Dispatch to user recv callback (no lock held)
            {
                WsClient::RecvCb cb;
                {
                    std::lock_guard<std::mutex> lk(impl->cb_mtx);
                    cb = impl->recv_cb;
                }
                if (cb)
                    cb(frame.opcode, frame.payload.data(), frame.payload.size());
            }
            break;
        }

        case WsOpcode::Pong:
            WS_DBG(*impl, "PONG len=%zu (ignored)\n", frame.payload.size());
            break;

        default:
            WS_ERR(*impl, "unknown opcode 0x%x — closing\n",
                   static_cast<uint8_t>(frame.opcode));
            {
                std::lock_guard<std::recursive_mutex> lk(impl->mtx);
                impl->recv_running = false;
                close_connection(*impl);
                notify_ack_waiters(*impl, nullptr);
            }
            keep_running = false;
            break;
        }
    }

    // Final safety net: close any still-open connection
    {
        std::lock_guard<std::recursive_mutex> lk(impl->mtx);
        if (impl->socket.valid()) {
            WS_INFO(*impl, "recv thread exit: socket still open — closing\n");
            close_connection(*impl);
        }
    }
    WS_INFO(*impl, "recv thread exited\n");
}

/* ══════════════════════════════════════════════════════════════════════════
 * WsClient public API
 * ══════════════════════════════════════════════════════════════════════════ */

WsClient::WsClient(Config cfg)
    : impl_(std::unique_ptr<Impl>(new Impl(std::move(cfg))))
{}

WsClient::~WsClient()
{
    if (impl_) disconnect(nullptr);
}

WsClient::WsClient(WsClient&&) noexcept            = default;
WsClient& WsClient::operator=(WsClient&&) noexcept = default;

void WsClient::set_recv_cb(RecvCb cb)
{
    std::lock_guard<std::mutex> lk(impl_->cb_mtx);
    impl_->recv_cb = std::move(cb);
}

int WsClient::connect(const std::string& url)
{
    std::lock_guard<std::recursive_mutex> lk(impl_->mtx);

    // No-op if already connected (also avoids overwriting a joinable thread).
    if (impl_->socket.valid()) {
        return 0;
    }

    impl_->url = url;

    int rc = connect_locked(*impl_);
    if (rc != 0) return rc;

    impl_->recv_running = true;
    impl_->recv_thread  = std::thread(recv_thread_fn, impl_.get());
    WS_INFO(*impl_, "connected — recv thread started\n");
    return 0;
}

void WsClient::disconnect(const char *reason)
{
    // Phase 1: signal shutdown and extract the thread (if joinable from here)
    std::thread to_join;
    {
        std::lock_guard<std::recursive_mutex> lk(impl_->mtx);
        impl_->recv_running = false;
        impl_->socket.shutdown_rw();

        if (impl_->recv_thread.joinable() &&
            impl_->recv_thread.get_id() != std::this_thread::get_id()) {
            to_join = std::move(impl_->recv_thread);
        }
    }

    // Phase 2: join OUTSIDE the lock so the recv thread can acquire it to exit
    if (to_join.joinable()) to_join.join();

    // Phase 3: free resources and wake any pending wait_for_ack() callers
    {
        std::lock_guard<std::recursive_mutex> lk(impl_->mtx);
        close_connection(*impl_);
        notify_ack_waiters(*impl_, reason);
    }

    WS_INFO(*impl_, "disconnected reason:%s\n", reason ? reason : "(error)");
}

bool WsClient::is_connected() const
{
    std::lock_guard<std::recursive_mutex> lk(impl_->mtx);
    return impl_->socket.valid();
}

int WsClient::send_text(const std::string& payload)
{
    std::lock_guard<std::recursive_mutex> lk(impl_->mtx);
    if (!impl_->socket.valid()) return -1;
    return send_data_frame(*impl_, WsOpcode::Text,
                           reinterpret_cast<const uint8_t*>(payload.data()),
                           payload.size()) ? 0 : -1;
}

int WsClient::send_binary(const uint8_t *data, std::size_t len)
{
    std::lock_guard<std::recursive_mutex> lk(impl_->mtx);
    if (!impl_->socket.valid()) return -1;
    return send_data_frame(*impl_, WsOpcode::Binary, data, len) ? 0 : -1;
}

void WsClient::prepare_for_ack()
{
    // Caller already holds impl_->mtx; only ack_mtx needed here
    std::lock_guard<std::mutex> lk(impl_->ack_mtx);
    impl_->ack_ready = false;
    impl_->ack_user_disabled = false;
    impl_->ack_resp.clear();
}

bool WsClient::wait_for_ack(unsigned long long   expected_id,
                             std::chrono::seconds timeout)
{
    if (timeout.count() == 0) timeout = impl_->ack_timeout;

    const std::string id_str = std::to_string(expected_id);
    const auto deadline = std::chrono::steady_clock::now() + timeout;

    std::unique_lock<std::mutex> lk(impl_->ack_mtx);

    bool signalled = impl_->ack_cv.wait_until(lk, deadline,
        [this]{ return impl_->ack_ready; });

    if (!signalled) {
        WS_ERR(*impl_, "ack timeout after %llds waiting for id:%llu\n",
               static_cast<long long>(timeout.count()), expected_id);
        return false;
    }

    bool matched = false;
    if (impl_->ack_resp.find("USER_DISABLED") != std::string::npos) {
        impl_->ack_user_disabled = true;
        WS_INFO(*impl_, "stream disabled — aborting ack wait for id:%llu\n",
                expected_id);
    } else if (impl_->ack_resp.find(id_str) != std::string::npos) {
        impl_->ack_user_disabled = false;
        WS_INFO(*impl_, "ack OK id:%llu resp:%s\n",
                expected_id, impl_->ack_resp.c_str());
        matched = true;
    } else {
        impl_->ack_user_disabled = false;
        WS_ERR(*impl_, "ack mismatch expected id:%llu resp:%s\n",
               expected_id, impl_->ack_resp.c_str());
    }
    impl_->ack_ready = false;
    return matched;
}

bool WsClient::last_ack_user_disabled() const
{
    std::lock_guard<std::mutex> lk(impl_->ack_mtx);
    return impl_->ack_user_disabled;
}

void WsClient::lock()   { impl_->mtx.lock(); }
void WsClient::unlock() { impl_->mtx.unlock(); }
