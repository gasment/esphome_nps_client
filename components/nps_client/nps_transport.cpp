#include "nps_transport.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "esp_crt_bundle.h"
#include "esphome/core/log.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"

namespace esphome::nps {
static const char *const TAG = "nps.transport";

// Go 1.26 服务端 TLS 1.3 偏好 RSA-PSS；显式声明与 Go 兼容的签名算法顺序。
static const uint16_t NPS_TLS_SIGNATURE_ALGORITHMS[] = {
    MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA256,
    MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256,
    MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA384,
    MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA512,
    MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA256,
    MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA384,
    MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA512,
    MBEDTLS_TLS1_3_SIG_ECDSA_SECP384R1_SHA384,
    MBEDTLS_TLS1_3_SIG_ECDSA_SECP521R1_SHA512,
    MBEDTLS_TLS1_3_SIG_NONE,
};

static std::string tls_error_(const char *prefix, int rc) {
  if (rc == MBEDTLS_ERR_NET_RECV_FAILED)
    return std::string(prefix) + ": socket receive failed";
  if (rc == MBEDTLS_ERR_NET_SEND_FAILED)
    return std::string(prefix) + ": socket send failed";
  if (rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
    return std::string(prefix) + ": peer closed connection";
  char buf[128];
  mbedtls_strerror(rc, buf, sizeof(buf));
  return std::string(prefix) + ": " + buf;
}

NpsTransport::NpsTransport() {
  mbedtls_ssl_init(&ssl_);
  mbedtls_ssl_config_init(&ssl_config_);
  mbedtls_entropy_init(&entropy_);
  mbedtls_ctr_drbg_init(&ctr_drbg_);
  mbedtls_x509_crt_init(&ca_);
}

NpsTransport::~NpsTransport() {
  close();
  mbedtls_ssl_free(&ssl_);
  mbedtls_ssl_config_free(&ssl_config_);
  mbedtls_ctr_drbg_free(&ctr_drbg_);
  mbedtls_entropy_free(&entropy_);
  mbedtls_x509_crt_free(&ca_);
}

bool NpsTransport::tcp_connect_(const char *server, uint16_t connect_timeout_s,
                                std::string &error) {
  std::string host(server);
  std::string port = "8024";
  size_t colon = host.rfind(':');
  if (colon != std::string::npos) {
    port = host.substr(colon + 1);
    host = host.substr(0, colon);
  }
  if (host.empty()) {
    error = "服务器地址为空";
    return false;
  }
  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  addrinfo *list = nullptr;
  int rc = getaddrinfo(host.c_str(), port.c_str(), &hints, &list);
  if (rc != 0 || list == nullptr) {
    error = "DNS 解析服务器失败: " + host;
    return false;
  }
  for (auto *p = list; p != nullptr; p = p->ai_next) {
    fd_ = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd_ < 0)
      continue;
    int flags = fcntl(fd_, F_GETFL, 0);
    fcntl(fd_, F_SETFL, flags | O_NONBLOCK);
    rc = ::connect(fd_, p->ai_addr, p->ai_addrlen);
    bool connected = rc == 0;
    if (rc < 0 && errno == EINPROGRESS) {
      fd_set wfds;
      FD_ZERO(&wfds);
      FD_SET(fd_, &wfds);
      timeval tv{static_cast<long>(connect_timeout_s), 0};
      rc = select(fd_ + 1, nullptr, &wfds, nullptr, &tv);
      if (rc > 0) {
        int e = 0;
        socklen_t n = sizeof(e);
        if (getsockopt(fd_, SOL_SOCKET, SO_ERROR, &e, &n) == 0 && e == 0)
          connected = true;
        else {
          if (e != 0)
            errno = e;
          connected = false;
        }
      } else if (rc == 0) {
        errno = ETIMEDOUT;
      }
    }
    if (connected) {
      peer_ip_[0] = '\0';
      if (p->ai_family == AF_INET) {
        inet_ntop(AF_INET,
                  &reinterpret_cast<sockaddr_in *>(p->ai_addr)->sin_addr,
                  peer_ip_, sizeof(peer_ip_));
      }
      ESP_LOGI(TAG, "服务器 %s 解析为 %s", server, peer_ip_);
      fcntl(fd_, F_SETFL, flags & ~O_NONBLOCK);
      int one = 1;
      setsockopt(fd_, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
      // 禁用 Nagle：窗口更新/控制帧都是小包，延迟会拖慢吞吐
      setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
      int idle = 30;
      int interval = 10;
      int count = 3;
      setsockopt(fd_, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
      setsockopt(fd_, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
      setsockopt(fd_, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
      freeaddrinfo(list);
      return true;
    }
    ::close(fd_);
    fd_ = -1;
  }
  freeaddrinfo(list);
  error = std::string("连接服务器失败: ") + strerror(errno);
  return false;
}

int NpsTransport::send_cb_(void *ctx, const unsigned char *buf, size_t len) {
  auto *self = static_cast<NpsTransport *>(ctx);
  int n = ::send(self->fd_, buf, len, 0);
  if (n >= 0)
    return n;
  self->last_socket_errno_ = errno;
  return (errno == EAGAIN || errno == EWOULDBLOCK) ? MBEDTLS_ERR_SSL_WANT_WRITE
                                                   : MBEDTLS_ERR_NET_SEND_FAILED;
}

int NpsTransport::recv_cb_(void *ctx, unsigned char *buf, size_t len) {
  auto *self = static_cast<NpsTransport *>(ctx);
  int n = ::recv(self->fd_, buf, len, 0);
  if (n > 0)
    return n;
  if (n == 0) {
    self->peer_closed_ = true;
    return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
  }
  self->last_socket_errno_ = errno;
  return (errno == EAGAIN || errno == EWOULDBLOCK) ? MBEDTLS_ERR_SSL_WANT_READ
                                                   : MBEDTLS_ERR_NET_RECV_FAILED;
}

bool NpsTransport::connect(const char *server, bool use_tls,
                           uint16_t connect_timeout_s, std::string &error) {
  close();
  last_socket_errno_ = 0;
  peer_closed_ = false;
  ESP_LOGI(TAG, "Connecting to %s (TLS=%s)", server, YESNO(use_tls));
  if (!tcp_connect_(server, connect_timeout_s, error))
    return false;
  if (!use_tls)
    return true;

  mbedtls_ssl_free(&ssl_);
  mbedtls_ssl_init(&ssl_);
  mbedtls_ssl_config_free(&ssl_config_);
  mbedtls_ssl_config_init(&ssl_config_);
  const char *personal = "esphome-nps";
  int rc = mbedtls_ctr_drbg_seed(
      &ctr_drbg_, mbedtls_entropy_func, &entropy_,
      reinterpret_cast<const unsigned char *>(personal), strlen(personal));
  if (rc != 0) {
    error = tls_error_("TLS 随机数初始化失败", rc);
    close();
    return false;
  }
  rc = mbedtls_ssl_config_defaults(&ssl_config_, MBEDTLS_SSL_IS_CLIENT,
                                   MBEDTLS_SSL_TRANSPORT_STREAM,
                                   MBEDTLS_SSL_PRESET_DEFAULT);
  if (rc != 0) {
    error = tls_error_("TLS 配置失败", rc);
    close();
    return false;
  }
  mbedtls_ssl_conf_sig_algs(&ssl_config_, NPS_TLS_SIGNATURE_ALGORITHMS);
  mbedtls_ssl_conf_rng(&ssl_config_, mbedtls_ctr_drbg_random, &ctr_drbg_);

  // nps 桥接 TLS 使用自签证书，客户端不做证书校验（与 npc InsecureSkipVerify 等价）
  mbedtls_ssl_conf_authmode(&ssl_config_, MBEDTLS_SSL_VERIFY_NONE);

  rc = mbedtls_ssl_setup(&ssl_, &ssl_config_);
  if (rc != 0) {
    error = tls_error_("TLS setup 失败", rc);
    close();
    return false;
  }
  mbedtls_ssl_set_bio(&ssl_, this, send_cb_, recv_cb_, nullptr);

  int sock_flags = fcntl(fd_, F_GETFL, 0);
  fcntl(fd_, F_SETFL, sock_flags | O_NONBLOCK);
  int idle = 0;
  while ((rc = mbedtls_ssl_handshake(&ssl_)) != 0) {
    if (rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE) {
      error = tls_error_("TLS 握手失败", rc);
      ESP_LOGE(TAG, "%s", error.c_str());
      close();
      return false;
    }
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd_, &fds);
    timeval tv{1, 0};
    int sr = select(fd_ + 1, (rc == MBEDTLS_ERR_SSL_WANT_READ) ? &fds : nullptr,
                    (rc == MBEDTLS_ERR_SSL_WANT_WRITE) ? &fds : nullptr,
                    nullptr, &tv);
    if (sr < 0) {
      error = "TLS 握手 select 失败";
      close();
      return false;
    }
    if (sr > 0)
      idle = 0;
    else if (++idle > static_cast<int>(connect_timeout_s)) {
      error = "TLS 握手超时";
      close();
      return false;
    }
  }
  fcntl(fd_, F_SETFL, sock_flags);
  tls_ = true;
  ESP_LOGI(TAG, "TLS handshake succeeded: %s", mbedtls_ssl_get_version(&ssl_));
  return true;
}

bool NpsTransport::read_all(uint8_t *data, size_t length, std::string &error) {
  size_t off = 0;
  while (off < length) {
    int n = tls_ ? mbedtls_ssl_read(&ssl_, data + off, length - off)
                 : ::recv(fd_, data + off, length - off, 0);
    if (n > 0) {
      off += static_cast<size_t>(n);
      continue;
    }
    if (tls_ && (n == MBEDTLS_ERR_SSL_WANT_READ ||
                 n == MBEDTLS_ERR_SSL_WANT_WRITE))
      continue;
    if (n == 0)
      error = "连接已关闭";
    else {
      int e = errno;
      error = "读取连接失败; socket errno=" + std::to_string(e) + " (" +
              strerror(e) + ")";
    }
    return false;
  }
  return true;
}

int NpsTransport::read_some(uint8_t *data, size_t length, std::string &error) {
  while (true) {
    int n = tls_ ? mbedtls_ssl_read(&ssl_, data, length)
                 : ::recv(fd_, data, length, 0);
    if (n > 0)
      return n;
    if (tls_ && (n == MBEDTLS_ERR_SSL_WANT_READ ||
                 n == MBEDTLS_ERR_SSL_WANT_WRITE))
      continue;
    if (n == 0)
      error = "连接已关闭";
    else {
      int e = errno;
      error = "读取连接失败; socket errno=" + std::to_string(e) + " (" +
              strerror(e) + ")";
    }
    return -1;
  }
}

bool NpsTransport::write_all(const uint8_t *data, size_t length,
                             std::string &error) {
  size_t off = 0;
  while (off < length) {
    int n = tls_ ? mbedtls_ssl_write(&ssl_, data + off, length - off)
                 : ::send(fd_, data + off, length - off, 0);
    if (n > 0) {
      off += static_cast<size_t>(n);
      continue;
    }
    if (tls_ && (n == MBEDTLS_ERR_SSL_WANT_READ ||
                 n == MBEDTLS_ERR_SSL_WANT_WRITE))
      continue;
    int e = errno;
    error = "写入连接失败; socket errno=" + std::to_string(e) + " (" +
            strerror(e) + ")";
    return false;
  }
  return true;
}

void NpsTransport::close() {
  if (tls_ && fd_ >= 0)
    mbedtls_ssl_close_notify(&ssl_);
  tls_ = false;
  if (fd_ >= 0) {
    shutdown(fd_, SHUT_RDWR);
    ::close(fd_);
    fd_ = -1;
  }
}

}  // namespace esphome::nps
