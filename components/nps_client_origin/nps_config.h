#pragma once

#include <cstdint>
#include <cstring>

namespace esphome::nps_origin {

// ehang-io/nps（旧版 0.26.x）客户端配置：
// 旧版无版本协商与加密认证，桥接仅 TCP，隧道 Crypt 仍为每流 TLS。
struct NpsConfig {
  bool enabled{false};
  char server[160]{};       // IP or domain only (no port)
  uint16_t tcp_port{8024};  // 桥接端口（旧版默认 8024）
  char vkey[128]{};         // verification key
  char legacy_version[16]{"0.26.0"};  // 核心版本串，必须与服务端 version.GetVersion() 一致
  uint16_t connect_timeout_s{10};
  uint16_t reconnect_delay_s{5};
  uint16_t disconnect_timeout_s{60};  // mux ping 超时
  bool use_psram{false};
};

}  // namespace esphome::nps_origin
