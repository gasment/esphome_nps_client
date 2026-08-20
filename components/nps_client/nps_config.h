#pragma once

#include <cstdint>
#include <cstring>

namespace esphome::nps {

struct NpsConfig {
  bool enabled{false};
  char server[160]{};       // IP or domain only (no port)
  char mode[8]{};           // "tcp" or "tls" (bridge transport)
  uint16_t tcp_port{8024};  // used when mode=tcp (nps default)
  uint16_t tls_port{8025};  // used when mode=tls (nps default)
  char vkey[128]{};         // verification key
  char local_ip[48]{};      // optional outbound IP override; empty = auto
  uint8_t proto_version{9};     // wire protocol version (5-9)
  uint16_t connect_timeout_s{10};
  uint16_t reconnect_delay_s{5};
  uint16_t disconnect_timeout_s{60};  // mux ping timeout
  bool use_psram{false};
};

}  // namespace esphome::nps
