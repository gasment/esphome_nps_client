#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"

namespace esphome::nps_origin {

// TCP / TLS 字节流传输。TLS 为标准 TLS（nps bridge_tls），无自定义首字节。
class NpsTransport {
 public:
  NpsTransport();
  ~NpsTransport();

  // server: "host:port"；tls_enable 时走 TLS。
  bool connect(const char *server, bool use_tls, uint16_t connect_timeout_s,
               std::string &error);
  bool read_all(uint8_t *data, size_t length, std::string &error);
  int read_some(uint8_t *data, size_t length, std::string &error);
  bool write_all(const uint8_t *data, size_t length, std::string &error);
  void close();
  bool connected() const { return fd_ >= 0; }
  int fd() const { return fd_; }
  bool tls() const { return tls_; }

 private:
  static int send_cb_(void *ctx, const unsigned char *buf, size_t len);
  static int recv_cb_(void *ctx, unsigned char *buf, size_t len);
  bool tcp_connect_(const char *server, uint16_t connect_timeout_s,
                    std::string &error);

  int fd_{-1};
  int last_socket_errno_{0};
  char peer_ip_[64]{};
  bool peer_closed_{false};
  bool tls_{false};
  mbedtls_ssl_context ssl_{};
  mbedtls_ssl_config ssl_config_{};
  mbedtls_entropy_context entropy_{};
  mbedtls_ctr_drbg_context ctr_drbg_{};
  mbedtls_x509_crt ca_{};
};

}  // namespace esphome::nps_origin
