/**
 * ws_client.h — Generic WebSocket client library (C++11)
 *
 * Thread-safety model:
 *   A std::recursive_mutex serialises all connection state.  Callers may
 *   hold it explicitly via lock() / unlock() for atomic multi-step sequences.
 *   Ack synchronisation uses a separate std::mutex + std::condition_variable,
 *   so wait_for_ack() can block without holding the main lock.
 *
 * Quick-start — send with ack:
 *   client.lock();
 *   client.connect(url);          // no-op if already connected
 *   client.prepare_for_ack();
 *   client.send_text(json);
 *   client.unlock();
 *   bool ok = client.wait_for_ack(order_id);
 *
 * Quick-start — receive-only (server push):
 *   client.set_recv_cb([](WsOpcode op, const uint8_t *d, std::size_t n) {
 *       // handle incoming frame
 *   });
 *   client.connect(url);
 */

#ifndef WS_CLIENT_H
#define WS_CLIENT_H

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

/** WebSocket frame opcodes per RFC 6455. */
enum class WsOpcode : uint8_t {
    Continuation = 0x0,
    Text         = 0x1,
    Binary       = 0x2,
    Close        = 0x8,
    Ping         = 0x9,
    Pong         = 0xA,
};

/**
 * WebSocket client.  Single connection per instance, fully thread-safe.
 * Non-copyable; movable.
 */
class WsClient {
public:
    /**
     * Callback invoked from the internal recv thread for every incoming
     * Text or Binary frame.
     *
     * WARNING: Do NOT call lock(), connect(), or disconnect() from within
     *          this callback — it runs on the recv thread.
     */
    using RecvCb = std::function<void(WsOpcode       opcode,
                                      const uint8_t *data,
                                      std::size_t    len)>;

    /** Construction configuration — all fields have sensible defaults. */
    struct Config {
        std::string          name        = "ws";   ///< Label used in log messages.
        bool                 verify_peer = false;  ///< TLS peer-cert verification.
        std::chrono::seconds ack_timeout {3};      ///< Default wait_for_ack() limit.
    };

    explicit WsClient(Config cfg);
    ~WsClient();

    WsClient(const WsClient&)            = delete;
    WsClient& operator=(const WsClient&) = delete;
    WsClient(WsClient&&)                 noexcept;
    WsClient& operator=(WsClient&&)      noexcept;

    /* ── Recv callback ───────────────────────────────────────────────────── */

    /** Register (or replace) the recv callback.  Pass {} to unregister. */
    void set_recv_cb(RecvCb cb);

    /* ── Connect / disconnect ────────────────────────────────────────────── */

    /**
     * Connect to ws[s]://host[:port]/path[?query].
     * Returns 0 on success, -1 on failure.  No-op if already connected.
     */
    int  connect(const std::string& url);

    /**
     * Disconnect and stop the recv thread.
     * @param reason  If non-null (e.g. "USER_DISABLED"), stored in the ack
     *                slot so that pending wait_for_ack() calls can detect a
     *                deliberate disconnect vs. a network error.
     */
    void disconnect(const char *reason = nullptr);

    /** Returns true when an open, usable connection exists. */
    bool is_connected() const;

    /* ── Send ────────────────────────────────────────────────────────────── */

    /** Send a WebSocket text frame (opcode 0x1). */
    int send_text(const std::string& payload);

    /** Send a WebSocket binary frame (opcode 0x2). */
    int send_binary(const uint8_t *data, std::size_t len);

    /* ── Request / response ack helpers ──────────────────────────────────── */

    /**
     * Clear the ack slot.  Call with the client lock held, immediately
     * before the send that expects a server acknowledgment.
     */
    void prepare_for_ack();

    /**
     * Block until the server sends a frame whose payload contains expected_id
     * as a decimal substring, or until timeout elapses.
     * Pass seconds{0} to use Config::ack_timeout.
     * Must be called WITHOUT the client lock held.
     */
    bool wait_for_ack(
        unsigned long long   expected_id,
        std::chrono::seconds timeout = std::chrono::seconds(0));

    /** True when the last wait_for_ack() observed USER_DISABLED. */
    bool last_ack_user_disabled() const;

    /* ── Explicit locking (advanced) ─────────────────────────────────────── */

    /**
     * Acquire the recursive client mutex.
     * Enables atomic multi-step sequences (see class-level documentation).
     */
    void lock();
    void unlock();

    /* ── Internal implementation detail ─────────────────────────────────── */
    struct Impl;   ///< Defined in ws_client.cpp (PIMPL).

private:
    std::unique_ptr<Impl> impl_;
};

#endif//WS_CLIENT_H
