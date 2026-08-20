#pragma once

#include <memory>
#include <string>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ssl.h"
#include "nps_mux.h"

namespace esphome::nps {

// 隧道级加密：在 mux 逻辑流上再套一层 TLS。
// 对应 Go 端 crypt.NewTlsClientConn（自签证书，InsecureSkipVerify）。
class NpsTlsStream {
 public:
  NpsTlsStream();
  ~NpsTlsStream();

  bool start(std::shared_ptr<NpsMuxConn> conn, uint32_t handshake_timeout_ms,
             std::string &error);
  int read_some(uint8_t *data, size_t length, uint32_t timeout_ms,
                std::string &error);
  bool write_all(const uint8_t *data, size_t length, std::string &error);
  void close();

 private:
  static int send_cb_(void *ctx, const unsigned char *buf, size_t len);
  static int recv_cb_(void *ctx, unsigned char *buf, size_t len);

  std::shared_ptr<NpsMuxConn> conn_;
  mbedtls_ssl_context ssl_{};
  mbedtls_ssl_config ssl_config_{};
  mbedtls_entropy_context entropy_{};
  mbedtls_ctr_drbg_context ctr_drbg_{};
  bool active_{false};
  uint32_t io_timeout_ms_{UINT32_MAX};
};

}  // namespace esphome::nps
