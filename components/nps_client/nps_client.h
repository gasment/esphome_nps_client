#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nps_config.h"
#include "nps_mux.h"
#include "nps_transport.h"

namespace esphome::nps {

class NpsClient {
 public:
  NpsClient();
  ~NpsClient();

  // 阻塞运行：连接-认证-mux-main-会话处理，断线后按配置延时重连。
  // config_provider 在每次（重）连接前调用获取最新配置；
  // reload 置位时结束当前会话并立即用新配置重连。
  bool run(const std::function<NpsConfig()> &config_provider,
           std::atomic<bool> &stop, std::atomic<bool> &reload,
           std::string &error);
  bool connected() const { return connected_.load(); }
  // 当前连接已持续秒数；未连接时为 0
  uint32_t connected_duration_s() const {
    int64_t since = connected_since_us_.load();
    if (since <= 0 || !connected_.load())
      return 0;
    return static_cast<uint32_t>((esp_timer_get_time() - since) / 1000000);
  }
  // 连接状态代数：每次 断/连 翻转 +1，用于事件驱动检测（避免轮询漏事件）
  uint32_t connection_epoch() const { return connection_epoch_.load(); }

 private:
  struct LinkInfo {
    std::string conn_type;
    std::string host;
    bool crypt{false};
    bool compress{false};
    int64_t timeout_ns{5000000000};
    bool need_ack{false};
    bool wait_connect_result{false};
  };

  static void accept_task_(void *arg);
  static void relay_task_(void *arg);
  static const char *version_for_(uint8_t ver);
  bool handshake_(uint8_t ver, size_t &rx_bytes, std::string &error);
  bool send_chan_(uint8_t ver, std::string &error);
  bool open_main_(uint8_t ver, std::string &error);
  void control_loop_(std::atomic<bool> &stop, std::atomic<bool> &reload);
  void accept_loop_();
  bool handle_conn_(const std::shared_ptr<NpsMuxConn> &conn,
                    std::string &error);
  bool dial_local_(const std::string &host, uint32_t timeout_ms, int &out_fd,
                   int &out_errno, std::string &error);
  bool read_len32_(std::string &error);
  bool read_len32_payload_(std::vector<uint8_t> &payload,
                           std::string &error);
  static bool get_local_ip_(char *out, size_t out_len);
  static void encode_ip_(const char *ip_str, uint8_t out[17]);

  NpsConfig config_{};
  std::unique_ptr<NpsTransport> transport_;
  std::shared_ptr<NpsMux> mux_;
  std::shared_ptr<NpsMuxConn> signal_;
  std::string uuid_;
  bool use_psram_{false};
  std::atomic<bool> connected_{false};
  std::atomic<int64_t> connected_since_us_{0};
  std::atomic<uint32_t> connection_epoch_{0};
  std::string last_server_;
  uint8_t last_proto_{0};
};

}  // namespace esphome::nps
