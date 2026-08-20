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

namespace esphome::nps_origin {

// ehang-io/nps（旧版 0.26.x）客户端：
// - 两条独立 TCP 连接：signal(main 控制) + chan(mux 数据)
// - 认证：TST + 版本 + md5(vkey) + sucs + 工作类型
// - 隧道会话：chan 上 mux Accept → LinkInfo → 拨号本地 → 双向中继
class NpsClient {
 public:
  NpsClient();
  ~NpsClient();

  // config_provider 在每次（重）连接前调用获取最新配置；
  // reload 置位时结束当前会话并立即用新配置重连。
  bool run(const std::function<NpsConfig()> &config_provider,
           std::atomic<bool> &stop, std::atomic<bool> &reload,
           std::string &error);
  bool connected() const { return connected_.load(); }
  uint32_t connected_duration_s() const {
    int64_t since = connected_since_us_.load();
    if (since <= 0 || !connected_.load())
      return 0;
    return static_cast<uint32_t>((esp_timer_get_time() - since) / 1000000);
  }
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

  // 旧版认证：建立一条 TCP 连接，完成版本校验 + md5(vkey) + 工作类型
  std::unique_ptr<NpsTransport> legacy_connect_(const char *work_type,
                                                std::string &error);
  bool read_len32_discard_(NpsTransport &t, std::string &error);
  void control_loop_(NpsTransport &signal, std::atomic<bool> &stop,
                     std::atomic<bool> &reload);
  void accept_loop_();
  bool handle_conn_(const std::shared_ptr<NpsMuxConn> &conn,
                    std::string &error);
  bool dial_local_(const std::string &host, uint32_t timeout_ms, int &out_fd,
                   int &out_errno, std::string &error);

  NpsConfig config_{};
  std::shared_ptr<NpsMux> mux_;
  bool use_psram_{false};
  std::string effective_legacy_version_;  // 最近一次匹配成功的核心版本
  std::atomic<bool> connected_{false};
  std::atomic<int64_t> connected_since_us_{0};
  std::atomic<uint32_t> connection_epoch_{0};
  std::string last_server_;
};

}  // namespace esphome::nps_origin
