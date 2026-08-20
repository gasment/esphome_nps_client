#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "nps_mem.h"
#include "nps_transport.h"

namespace esphome::nps_origin {

class NpsMux;

// mux 上的一条逻辑流（对应一个隧道会话或 main 信令）。
class NpsMuxConn {
 public:
  ~NpsMuxConn();

  bool read_all(uint8_t *data, size_t length, std::string &error);
  int read_some(uint8_t *data, size_t length, uint32_t timeout_ms,
                std::string &error);
  bool write_all(const uint8_t *data, size_t length, std::string &error);
  bool wait_readable(uint32_t timeout_ms);
  void close();
  int32_t id() const { return id_; }
  std::shared_ptr<NpsMux> mux() const { return mux_; }

 private:
  friend class NpsMux;
  NpsMuxConn(std::shared_ptr<NpsMux> mux, int32_t id,
             NpsPsRamResource *psram_resource);

  void receive_(const uint8_t *payload, size_t length);
  void apply_window_update_(uint64_t packed);
  void remote_close_();
  void remote_write_close_();
  void fail_(const std::string &error);
  bool valid_() const { return mutex_ != nullptr && data_ready_ != nullptr && send_ready_ != nullptr; }
  void send_pending_window_update_();

  std::shared_ptr<NpsMux> mux_;
  int32_t id_;
  SemaphoreHandle_t mutex_{nullptr};
  SemaphoreHandle_t data_ready_{nullptr};
  SemaphoreHandle_t send_ready_{nullptr};
  std::pmr::vector<uint8_t> receive_buffer_;
  size_t receive_offset_{0};
  uint32_t consumed_since_update_{0};
  // 发送窗口（与 Go sendWindow 语义一致：sent 表示自上次窗口更新以来的未确认发送量）
  uint32_t send_window_max_{122550};
  uint32_t send_sent_{0};
  bool remote_closed_{false};
  bool remote_write_closed_{false};
  bool local_closed_{false};
  std::string error_;
};

class NpsMux : public std::enable_shared_from_this<NpsMux> {
 public:
  enum : uint8_t {
    FLAG_PING = 0,
    FLAG_NEW_CONN_OK = 1,
    FLAG_NEW_CONN_FAIL = 2,
    FLAG_NEW_MSG = 3,
    FLAG_NEW_MSG_PART = 4,
    FLAG_MSG_SEND_OK = 5,
    FLAG_NEW_CONN = 6,
    FLAG_CONN_CLOSE = 7,
    FLAG_PING_RETURN = 8,
    FLAG_PEER_HELLO = 9,
    FLAG_CONN_CLOSE_WRITE = 10,
  };

  NpsMux();
  ~NpsMux();

  // 在已认证的 chan 连接上启动 mux（随后双方都会发 peer hello）。
  bool start(std::unique_ptr<NpsTransport> transport, bool use_psram,
             uint16_t ping_timeout_s, std::string &error);
  // 旧版 ehang-io/nps-mux 不发送能力协商帧，legacy 模式跳过 peerHello
  void set_legacy_no_hello(bool value) { legacy_no_hello_ = value; }
  std::shared_ptr<NpsMuxConn> open_stream(std::string &error);
  std::shared_ptr<NpsMuxConn> accept_stream(uint32_t timeout_ms,
                                            std::string &error);
  void close();
  bool running() const { return running_.load(); }
  int fd() const { return transport_ ? transport_->fd() : -1; }
  uint16_t ping_timeout_s() const { return ping_timeout_s_; }

 private:
  friend class NpsMuxConn;
  static constexpr uint32_t SEGMENT_SIZE = 4085;
  static constexpr uint32_t DEFAULT_INITIAL_WINDOW = 122550;  // 4085 * 30
  static constexpr uint32_t WINDOW_MASK = 0x7FFFFFFF;
  static constexpr int32_t PING_STREAM_ID = -1;
  uint32_t initial_window() const { return initial_window_; }

  static void reader_entry_(void *arg);
  static void ping_entry_(void *arg);
  void reader_();
  void ping_();
  bool send_frame_(uint8_t flag, int32_t id, const uint8_t *payload,
                   size_t payload_len, uint64_t window, bool has_window,
                   std::string &error);
  bool send_window_update_(int32_t id, uint32_t consumed, std::string &error);
  void remove_stream_(int32_t id);
  void fail_all_(const std::string &error);
  std::shared_ptr<NpsMuxConn> find_stream_(int32_t id);
  void mark_alive_() { last_frame_us_.store(esp_timer_get_time()); }

  std::unique_ptr<NpsTransport> transport_;
  NpsPsRamResource psram_resource_;
  SemaphoreHandle_t streams_mutex_{nullptr};
  SemaphoreHandle_t write_mutex_{nullptr};
  SemaphoreHandle_t accept_mutex_{nullptr};
  SemaphoreHandle_t accept_ready_{nullptr};
  SemaphoreHandle_t reader_stopped_{nullptr};
  SemaphoreHandle_t ping_stopped_{nullptr};
  std::map<int32_t, std::shared_ptr<NpsMuxConn>> streams_;
  std::deque<std::shared_ptr<NpsMuxConn>> accept_queue_;
  int32_t next_stream_id_{-1};
  std::atomic<bool> running_{false};
  TaskHandle_t reader_task_{nullptr};
  TaskHandle_t ping_task_{nullptr};
  std::atomic<int64_t> last_frame_us_{0};
  uint16_t ping_timeout_s_{60};
  bool use_psram_{false};
  uint32_t initial_window_{DEFAULT_INITIAL_WINDOW};
  bool legacy_no_hello_{false};
};

}  // namespace esphome::nps_origin
