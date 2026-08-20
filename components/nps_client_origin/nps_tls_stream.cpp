#include "nps_tls_stream.h"

#include <cstring>

#include "esp_timer.h"
#include "esphome/core/log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"

namespace esphome::nps_origin {
static const char *const TAG = "nps.tls";

static std::string tls_error_(const char *prefix, int rc) {
  if (rc == MBEDTLS_ERR_NET_RECV_FAILED)
    return std::string(prefix) + ": 接收失败";
  if (rc == MBEDTLS_ERR_NET_SEND_FAILED)
    return std::string(prefix) + ": 发送失败";
  if (rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
    return std::string(prefix) + ": 对端关闭";
  char buf[128];
  mbedtls_strerror(rc, buf, sizeof(buf));
  return std::string(prefix) + ": " + buf;
}

NpsTlsStream::NpsTlsStream() {
  mbedtls_ssl_init(&ssl_);
  mbedtls_ssl_config_init(&ssl_config_);
  mbedtls_entropy_init(&entropy_);
  mbedtls_ctr_drbg_init(&ctr_drbg_);
}

NpsTlsStream::~NpsTlsStream() {
  close();
  mbedtls_ssl_free(&ssl_);
  mbedtls_ssl_config_free(&ssl_config_);
  mbedtls_ctr_drbg_free(&ctr_drbg_);
  mbedtls_entropy_free(&entropy_);
}

int NpsTlsStream::send_cb_(void *ctx, const unsigned char *buf, size_t len) {
  auto *self = static_cast<NpsTlsStream *>(ctx);
  if (self->conn_ == nullptr)
    return MBEDTLS_ERR_NET_SEND_FAILED;
  std::string error;
  if (!self->conn_->write_all(buf, len, error))
    return MBEDTLS_ERR_NET_SEND_FAILED;
  return static_cast<int>(len);
}

int NpsTlsStream::recv_cb_(void *ctx, unsigned char *buf, size_t len) {
  auto *self = static_cast<NpsTlsStream *>(ctx);
  if (self->conn_ == nullptr)
    return 0;
  std::string error;
  int n = self->conn_->read_some(buf, len, self->io_timeout_ms_, error);
  if (n > 0)
    return n;
  if (n == 0)
    return MBEDTLS_ERR_SSL_WANT_READ;  // 超时无数据
  return 0;  // 流关闭，视为对端干净关闭
}

bool NpsTlsStream::start(std::shared_ptr<NpsMuxConn> conn,
                         uint32_t handshake_timeout_ms, std::string &error) {
  conn_ = std::move(conn);
  const char *personal = "esphome-nps-tunnel";
  int rc = mbedtls_ctr_drbg_seed(
      &ctr_drbg_, mbedtls_entropy_func, &entropy_,
      reinterpret_cast<const unsigned char *>(personal), strlen(personal));
  if (rc != 0) {
    error = tls_error_("隧道 TLS 随机数初始化失败", rc);
    return false;
  }
  rc = mbedtls_ssl_config_defaults(&ssl_config_, MBEDTLS_SSL_IS_CLIENT,
                                   MBEDTLS_SSL_TRANSPORT_STREAM,
                                   MBEDTLS_SSL_PRESET_DEFAULT);
  if (rc != 0) {
    error = tls_error_("隧道 TLS 配置失败", rc);
    return false;
  }
  // nps 隧道加密使用自签证书，客户端不做校验（与 npc InsecureSkipVerify 等价）
  mbedtls_ssl_conf_authmode(&ssl_config_, MBEDTLS_SSL_VERIFY_NONE);
  mbedtls_ssl_conf_rng(&ssl_config_, mbedtls_ctr_drbg_random, &ctr_drbg_);
  rc = mbedtls_ssl_setup(&ssl_, &ssl_config_);
  if (rc != 0) {
    error = tls_error_("隧道 TLS setup 失败", rc);
    return false;
  }
  mbedtls_ssl_set_bio(&ssl_, this, send_cb_, recv_cb_, nullptr);

  io_timeout_ms_ = handshake_timeout_ms > 0 ? handshake_timeout_ms : 10000;
  int64_t deadline = esp_timer_get_time() +
                     static_cast<int64_t>(handshake_timeout_ms) * 1000;
  while ((rc = mbedtls_ssl_handshake(&ssl_)) != 0) {
    if (rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE) {
      error = tls_error_("隧道 TLS 握手失败", rc);
      ESP_LOGW(TAG, "%s", error.c_str());
      return false;
    }
    if (esp_timer_get_time() > deadline) {
      error = "隧道 TLS 握手超时";
      ESP_LOGW(TAG, "%s", error.c_str());
      return false;
    }
  }
  active_ = true;
  ESP_LOGI(TAG, "隧道 TLS 握手完成: %s", mbedtls_ssl_get_version(&ssl_));
  return true;
}

int NpsTlsStream::read_some(uint8_t *data, size_t length, uint32_t timeout_ms,
                            std::string &error) {
  if (!active_ || conn_ == nullptr) {
    error = "隧道 TLS 未建立";
    return -1;
  }
  io_timeout_ms_ = timeout_ms;
  int n = mbedtls_ssl_read(&ssl_, data, length);
  if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE)
    return 0;  // 超时无数据
  if (n < 0) {
    error = "隧道 TLS 读取结束";
    return -1;
  }
  return n;
}

bool NpsTlsStream::write_all(const uint8_t *data, size_t length,
                             std::string &error) {
  if (!active_ || conn_ == nullptr) {
    error = "隧道 TLS 未建立";
    return false;
  }
  size_t off = 0;
  int spin = 0;
  while (off < length) {
    int n = mbedtls_ssl_write(&ssl_, data + off, length - off);
    if (n > 0) {
      off += static_cast<size_t>(n);
      spin = 0;
      continue;
    }
    if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) {
      if (++spin > 200) {
        error = "隧道 TLS 写入阻塞超时";
        return false;
      }
      vTaskDelay(pdMS_TO_TICKS(1));
      continue;
    }
    error = tls_error_("隧道 TLS 写入失败", n);
    return false;
  }
  return true;
}

void NpsTlsStream::close() {
  if (active_ && conn_ != nullptr) {
    mbedtls_ssl_close_notify(&ssl_);
    active_ = false;
  }
}

}  // namespace esphome::nps_origin
