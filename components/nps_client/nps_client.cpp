#include "nps_client.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "esp_netif.h"
#include "esp_random.h"
#include "esphome/core/log.h"
#include "lwip/ip4_addr.h"
#include "nps_crypto.h"
#include "nps_json.h"
#include "nps_mem.h"
#include "nps_tls_stream.h"

namespace esphome::nps {
static const char *const TAG = "nps.client";

static constexpr size_t MAX_PAYLOAD = 1 << 20;
static constexpr uint32_t RELAY_BUFFER = 8192;

#if defined(CONFIG_IDF_TARGET_ARCH_RISCV)
static constexpr uint32_t ACCEPT_STACK = 8192;
static constexpr uint32_t RELAY_STACK = 12288;
#else
static constexpr uint32_t ACCEPT_STACK = 8192;
static constexpr uint32_t RELAY_STACK = 14336;
#endif

struct RelayCtx {
  NpsClient *client;
  std::shared_ptr<NpsMuxConn> conn;
};

NpsClient::NpsClient() = default;
NpsClient::~NpsClient() { connected_ = false; }

bool NpsClient::get_local_ip_(char *out, size_t out_len) {
  esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  if (netif == nullptr)
    netif = esp_netif_get_handle_from_ifkey("ETH_DEF");
  if (netif == nullptr)
    return false;
  esp_netif_ip_info_t ip;
  if (esp_netif_get_ip_info(netif, &ip) != ESP_OK)
    return false;
  if (esp_ip4addr_ntoa(&ip.ip, out, static_cast<int>(out_len)) == nullptr)
    return false;
  return true;
}

void NpsClient::encode_ip_(const char *ip_str, uint8_t out[17]) {
  memset(out, 0, 17);
  if (ip_str == nullptr || ip_str[0] == '\0') {
    out[0] = 0x01;
    out[1] = 127;
    out[2] = 0;
    out[3] = 0;
    out[4] = 1;
    return;
  }
  uint8_t ip4[4];
  if (inet_pton(AF_INET, ip_str, ip4) == 1) {
    out[0] = 0x01;
    memcpy(out + 1, ip4, 4);
    return;
  }
  uint8_t ip6[16];
  if (inet_pton(AF_INET6, ip_str, ip6) == 1) {
    out[0] = 0x04;
    memcpy(out + 1, ip6, 16);
    return;
  }
  out[0] = 0x01;
  out[1] = 127;
  out[2] = 0;
  out[3] = 0;
  out[4] = 1;
}

bool NpsClient::read_len32_(std::string &error) {
  uint8_t lenbuf[4];
  if (transport_ == nullptr)
    return false;
  if (!transport_->read_all(lenbuf, sizeof(lenbuf), error))
    return false;
  uint32_t len = (static_cast<uint32_t>(lenbuf[3]) << 24) |
                 (static_cast<uint32_t>(lenbuf[2]) << 16) |
                 (static_cast<uint32_t>(lenbuf[1]) << 8) | lenbuf[0];
  if (len > MAX_PAYLOAD) {
    error = "长度前缀超限";
    return false;
  }
  if (len == 0)
    return true;
  std::vector<uint8_t> buf(len);
  return transport_->read_all(buf.data(), len, error);
}

bool NpsClient::read_len32_payload_(std::vector<uint8_t> &payload,
                                    std::string &error) {
  uint8_t lenbuf[4];
  if (signal_ == nullptr || !signal_->read_all(lenbuf, sizeof(lenbuf), error))
    return false;
  uint32_t len = (static_cast<uint32_t>(lenbuf[3]) << 24) |
                 (static_cast<uint32_t>(lenbuf[2]) << 16) |
                 (static_cast<uint32_t>(lenbuf[1]) << 8) | lenbuf[0];
  if (len > MAX_PAYLOAD) {
    error = "信令载荷超限";
    return false;
  }
  payload.assign(len, 0);
  if (len > 0 && !signal_->read_all(payload.data(), len, error))
    return false;
  return true;
}

const char *NpsClient::version_for_(uint8_t ver) {
  switch (ver) {
    case 9:
      return "0.35.0";
    case 8:
      return "0.34.0";
    case 7:
      return "0.33.0";
    case 6:
      return "0.32.0";
    case 5:
      return "0.31.0";
    case 4:
      return "0.30.0";
    case 3:
      return "0.29.0";
    case 2:
      return "0.28.0";
    case 1:
      return "0.27.0";
    default:
      return "0.26.0";
  }
}

bool NpsClient::handshake_(uint8_t ver, size_t &rx_bytes,
                           std::string &error) {
  const char *min_version = version_for_(ver);
  const char *version = "0.35.0";  // version.VERSION（无论 proto 版本）
  const bool use_tls = strcmp(config_.mode, "tls") == 0;
  const char *tp = use_tls ? "tls" : "tcp";
  rx_bytes = 0;

  auto rx_all = [&](uint8_t *data, size_t length) {
    if (!transport_->read_all(data, length, error))
      return false;
    rx_bytes += length;
    return true;
  };

  // ---- 版本包 ----
  std::vector<uint8_t> version_bytes(
      reinterpret_cast<const uint8_t *>(version),
      reinterpret_cast<const uint8_t *>(version) + strlen(version));
  size_t pad = esp_random() % 64;
  if (pad > 0) {
    uint8_t padbuf[64] = {0};  // Go: make([]byte, padLen) 全零，服务器会 trim
    version_bytes.insert(version_bytes.end(), padbuf, padbuf + pad);
  }
  std::vector<uint8_t> version_msg;
  version_msg.insert(version_msg.end(),
                     reinterpret_cast<const uint8_t *>("TST"),
                     reinterpret_cast<const uint8_t *>("TST") + 3);
  nps_append_len32(version_msg,
                   reinterpret_cast<const uint8_t *>(min_version),
                   strlen(min_version));
  nps_append_len32(version_msg, version_bytes.data(), version_bytes.size());
  if (!transport_->write_all(version_msg.data(), version_msg.size(), error))
    return false;

  // ---- 认证包 ----
  int64_t now = static_cast<int64_t>(time(nullptr));
  if (now < 1700000000)
    ESP_LOGW(TAG, "系统时间未同步（ts=%lld），若服务器开启安全模式将认证失败",
             static_cast<long long>(now));
  int64_t timestamp = now - static_cast<int64_t>(esp_random() % 6);

  char ip_str[48] = "127.0.0.1";
  if (config_.local_ip[0]) {
    snprintf(ip_str, sizeof(ip_str), "%s", config_.local_ip);
  } else {
    char detected[48];
    if (get_local_ip_(detected, sizeof(detected)))
      snprintf(ip_str, sizeof(ip_str), "%s", detected);
  }
  uint8_t info_plain[64];
  encode_ip_(ip_str, info_plain);
  size_t tp_len = strlen(tp);
  info_plain[17] = static_cast<uint8_t>(tp_len);
  memcpy(info_plain + 18, tp, tp_len);

  uint8_t aes_key[32];
  nps_vkey_aes_key(config_.vkey, aes_key);
  std::vector<uint8_t> info_enc;
  if (!nps_aes_gcm_encrypt(aes_key, info_plain, 18 + tp_len, info_enc)) {
    error = "加密认证信息失败";
    return false;
  }

  std::vector<uint8_t> rand_buf(esp_random() % 1001);
  if (!rand_buf.empty())
    nps_random_bytes(rand_buf.data(), rand_buf.size());

  std::vector<std::vector<uint8_t>> hmac_pieces;
  hmac_pieces.push_back(
      std::vector<uint8_t>(reinterpret_cast<const uint8_t *>(min_version),
                           reinterpret_cast<const uint8_t *>(min_version) +
                               strlen(min_version)));
  hmac_pieces.push_back(version_bytes);
  hmac_pieces.push_back(info_enc);
  hmac_pieces.push_back(rand_buf);
  uint8_t hmac[32];
  nps_compute_hmac(config_.vkey, timestamp, hmac_pieces, hmac);

  std::string blake = nps_blake2b_hex(config_.vkey);
  std::vector<uint8_t> auth_msg;
  uint8_t ts_be[8];
  nps_timestamp_be(timestamp, ts_be);
  auth_msg.insert(auth_msg.end(), ts_be, ts_be + 8);
  auth_msg.insert(auth_msg.end(), blake.begin(), blake.end());
  nps_append_len32(auth_msg, info_enc.data(), info_enc.size());
  nps_append_len32(auth_msg, rand_buf.data(), rand_buf.size());
  auth_msg.insert(auth_msg.end(), hmac, hmac + 32);
  if (!transport_->write_all(auth_msg.data(), auth_msg.size(), error))
    return false;

  // ---- 认证响应 ----
  uint8_t resp[32];
  if (!rx_all(resp, sizeof(resp)))
    return false;
  std::vector<std::vector<uint8_t>> expect_pieces;
  expect_pieces.push_back(std::vector<uint8_t>(hmac, hmac + 32));
  expect_pieces.push_back(
      std::vector<uint8_t>(reinterpret_cast<const uint8_t *>(min_version),
                           reinterpret_cast<const uint8_t *>(min_version) +
                               strlen(min_version)));
  uint8_t expected[32];
  nps_compute_hmac(config_.vkey, timestamp, expect_pieces, expected);
  if (memcmp(resp, expected, 32) != 0) {
    error = "服务端认证响应不匹配（协议版本不一致或 vkey 错误）";
    return false;
  }
  if (ver > 1) {
    uint8_t lenbuf[4];
    if (!rx_all(lenbuf, sizeof(lenbuf)))
      return false;
    uint32_t fp_len = (static_cast<uint32_t>(lenbuf[3]) << 24) |
                      (static_cast<uint32_t>(lenbuf[2]) << 16) |
                      (static_cast<uint32_t>(lenbuf[1]) << 8) | lenbuf[0];
    if (fp_len > 4096) {
      error = "证书指纹长度异常";
      return false;
    }
    std::vector<uint8_t> discard(fp_len);
    if (fp_len > 0 && !rx_all(discard.data(), fp_len))
      return false;
  }
  if (ver > 5) {
    uint8_t lenbuf[4];
    if (!rx_all(lenbuf, sizeof(lenbuf)))
      return false;
    uint32_t uuid_len = (static_cast<uint32_t>(lenbuf[3]) << 24) |
                        (static_cast<uint32_t>(lenbuf[2]) << 16) |
                        (static_cast<uint32_t>(lenbuf[1]) << 8) | lenbuf[0];
    if (uuid_len > 512) {
      error = "uuid 长度异常";
      return false;
    }
    std::vector<uint8_t> uuid_buf(uuid_len);
    if (uuid_len > 0 && !rx_all(uuid_buf.data(), uuid_len))
      return false;
    uuid_.assign(reinterpret_cast<char *>(uuid_buf.data()),
                 uuid_buf.size());
  } else {
    uuid_.clear();
  }
  if (ver > 3) {
    if (!read_len32_(error)) {
      rx_bytes += 4;
      return false;
    }
  }
  ESP_LOGI(TAG, "认证成功 proto=%u uuid=%s", static_cast<unsigned>(ver),
           uuid_.c_str());
  return true;
}

bool NpsClient::send_chan_(uint8_t ver, std::string &error) {
  std::vector<uint8_t> msg(
      reinterpret_cast<const uint8_t *>("chan"),
      reinterpret_cast<const uint8_t *>("chan") + 4);
  if (ver > 5) {
    nps_append_len32(msg, reinterpret_cast<const uint8_t *>(uuid_.data()),
                     uuid_.size());
  }
  if (ver > 3) {
    std::vector<uint8_t> rand_buf(esp_random() % 1001);
    if (!rand_buf.empty())
      nps_random_bytes(rand_buf.data(), rand_buf.size());
    nps_append_len32(msg, rand_buf.data(), rand_buf.size());
  }
  if (!transport_->write_all(msg.data(), msg.size(), error))
    return false;
  ESP_LOGI(TAG, "chan 工作类型已发送 (proto=%u)",
           static_cast<unsigned>(ver));
  return true;
}

bool NpsClient::open_main_(uint8_t ver, std::string &error) {
  mux_ = std::make_shared<NpsMux>();
  if (!mux_->start(std::move(transport_), use_psram_,
                   config_.disconnect_timeout_s, error))
    return false;
  signal_ = mux_->open_stream(error);
  if (signal_ == nullptr)
    return false;
  std::vector<uint8_t> msg(
      reinterpret_cast<const uint8_t *>("main"),
      reinterpret_cast<const uint8_t *>("main") + 4);
  if (ver > 5) {
    nps_append_len32(msg, reinterpret_cast<const uint8_t *>(uuid_.data()),
                     uuid_.size());
  }
  if (ver > 3) {
    std::vector<uint8_t> rand_buf(esp_random() % 1001);
    if (!rand_buf.empty())
      nps_random_bytes(rand_buf.data(), rand_buf.size());
    nps_append_len32(msg, rand_buf.data(), rand_buf.size());
  }
  if (!signal_->write_all(msg.data(), msg.size(), error))
    return false;
  connected_ = true;
  connected_since_us_.store(esp_timer_get_time());
  connection_epoch_.fetch_add(1);
  ESP_LOGI(TAG, "main 信令就绪，隧道待命");
  if (xTaskCreate(accept_task_, "nps_accept", ACCEPT_STACK, this, 4, nullptr) !=
      pdPASS) {
    error = "创建 accept 任务失败";
    return false;
  }
  return true;
}

void NpsClient::accept_task_(void *arg) {
  static_cast<NpsClient *>(arg)->accept_loop_();
  vTaskDelete(nullptr);
}

void NpsClient::accept_loop_() {
  auto mux = mux_;
  while (mux != nullptr && mux->running()) {
    std::string error;
    auto conn = mux->accept_stream(1000, error);
    if (conn == nullptr) {
      if (!mux->running())
        break;
      continue;
    }
    ESP_LOGI(TAG, "收到新逻辑流 id=%d", static_cast<int>(conn->id()));
    auto *ctx = new RelayCtx{this, conn};
    if (xTaskCreate(relay_task_, "nps_relay", RELAY_STACK, ctx, 4, nullptr) !=
        pdPASS) {
      delete ctx;
      conn->close();
    }
  }
  ESP_LOGD(TAG, "accept 循环结束");
}

void NpsClient::relay_task_(void *arg) {
  auto *ctx = static_cast<RelayCtx *>(arg);
  std::string error;
  if (!ctx->client->handle_conn_(ctx->conn, error))
    ESP_LOGW(TAG, "会话结束: %s", error.c_str());
  ESP_LOGD(TAG, "relay 任务栈余量 %lu 字节",
           static_cast<unsigned long>(uxTaskGetStackHighWaterMark(nullptr)));
  delete ctx;
  vTaskDelete(nullptr);
}

bool NpsClient::handle_conn_(const std::shared_ptr<NpsMuxConn> &conn,
                             std::string &error) {
  auto mux = conn->mux();
  // 1) LinkInfo: int32 LE 长度 + JSON
  uint8_t lenbuf[4];
  if (!conn->read_all(lenbuf, sizeof(lenbuf), error))
    return false;
  uint32_t len = (static_cast<uint32_t>(lenbuf[3]) << 24) |
                 (static_cast<uint32_t>(lenbuf[2]) << 16) |
                 (static_cast<uint32_t>(lenbuf[1]) << 8) | lenbuf[0];
  if (len == 0 || len > 65536) {
    error = "LinkInfo 长度异常";
    return false;
  }
  std::vector<uint8_t> payload(len);
  if (!conn->read_all(payload.data(), len, error))
    return false;
  std::string json(reinterpret_cast<char *>(payload.data()), payload.size());
  ESP_LOGD(TAG, "LinkInfo: %.256s", json.c_str());
  LinkInfo lk;
  lk.conn_type = nps_json_string(json, "ConnType");
  lk.host = nps_json_string(json, "Host");
  lk.crypt = nps_json_bool(json, "Crypt", false);
  lk.compress = nps_json_bool(json, "Compress", false);
  lk.timeout_ns = nps_json_int64(json, "Option.Timeout", 5000000000);
  lk.need_ack = nps_json_bool(json, "Option.NeedAck", false);
  lk.wait_connect_result =
      nps_json_bool(json, "Option.WaitConnectResult", false);

  ESP_LOGD(TAG, "新会话 type=%s host=%s crypt=%d compress=%d ack=%d result=%d",
           lk.conn_type.c_str(), lk.host.c_str(), lk.crypt ? 1 : 0,
           lk.compress ? 1 : 0, lk.need_ack ? 1 : 0,
           lk.wait_connect_result ? 1 : 0);

  if (lk.need_ack) {
    if (!conn->write_all(reinterpret_cast<const uint8_t *>("ACK"), 3, error)) {
      ESP_LOGW(TAG, "ACK 发送失败: %s", error.c_str());
      return false;
    }
    ESP_LOGI(TAG, "ACK 已发送");
  }
  if (lk.conn_type != "tcp") {
    if (lk.conn_type == "ping") {
      // 不主动关闭：服务端 ReadACK 完成后会自己 close 这个流。
      // 主动 close 会和服务端 receiveWindow.Stop() 竞争，导致 ReadACK
      // 失败、整条隧道被服务端关闭（隧道活跃时尤其容易触发）。
      ESP_LOGI(TAG, "ping 流已回 ACK，等待服务端关闭");
    } else {
      ESP_LOGW(TAG, "暂不支持 %s 模式，关闭会话", lk.conn_type.c_str());
      conn->close();
    }
    return true;
  }
  if (lk.host.empty()) {
    conn->close();
    return true;
  }
  if (lk.compress) {
    ESP_LOGW(TAG, "隧道开启了压缩（snappy），ESP32 客户端暂不支持，请在服务端关闭");
    if (lk.wait_connect_result) {
      uint8_t res[2] = {1, 255};
      conn->write_all(res, sizeof(res), error);
    }
    conn->close();
    return true;
  }
  if (lk.crypt) {
    ESP_LOGI(TAG, "隧道启用加密，将建立 TLS 会话");
  }

  int64_t timeout_ms = lk.timeout_ns / 1000000;
  if (timeout_ms <= 0)
    timeout_ms = 5000;
  if (timeout_ms > 30000)
    timeout_ms = 30000;
  int local = -1;
  int dial_errno = 0;
  if (!dial_local_(lk.host, static_cast<uint32_t>(timeout_ms), local,
                   dial_errno, error)) {
    if (lk.wait_connect_result) {
      uint8_t status = 255;
      switch (dial_errno) {
        case ECONNREFUSED:
          status = 1;
          break;
        case EHOSTUNREACH:
          status = 2;
          break;
        case ENETUNREACH:
        case ETIMEDOUT:
          status = 3;
          break;
        case EACCES:
        case EPERM:
          status = 4;
          break;
        default:
          status = 255;
          break;
      }
      uint8_t res[2] = {1, status};
      conn->write_all(res, sizeof(res), error);
    }
    conn->close();
    return false;
  }
  if (lk.wait_connect_result) {
    uint8_t res[2] = {1, 0};
    if (!conn->write_all(res, sizeof(res), error)) {
      ::close(local);
      conn->close();
      return false;
    }
  }

  std::unique_ptr<NpsTlsStream> tls;
  if (lk.crypt) {
    tls = std::make_unique<NpsTlsStream>();
    if (!tls->start(conn, 10000, error)) {
      ::close(local);
      conn->close();
      return false;
    }
  }

  uint8_t *buf = nps_alloc(RELAY_BUFFER, use_psram_);
  if (buf == nullptr) {
    error = "OOM";
    ::close(local);
    conn->close();
    return false;
  }
  ESP_LOGD(TAG, "开始转发 host=%s", lk.host.c_str());
  // 事件驱动中继：隧道方向由数据就绪信号量驱动连续搬空，不再受轮询周期限制；
  // 本地方向非阻塞顺带检查。空闲时阻塞等隧道（带超时）避免空转。
  constexpr uint32_t IDLE_WAIT_MS = 20;
  constexpr int MAX_DRAIN_CHUNKS = 16;  // 每轮最多 16*8KB=128KB，防止饿死本地方向
  bool relay_ok = true;
  while (mux != nullptr && mux->running() && relay_ok) {
    bool progress = false;
    // 隧道 → 本地：有数据就连续搬多块
    for (int chunks = 0; chunks < MAX_DRAIN_CHUNKS; chunks++) {
      int n = 0;
      if (tls) {
        n = tls->read_some(buf, RELAY_BUFFER, 0, error);
      } else if (conn->wait_readable(0)) {
        n = conn->read_some(buf, RELAY_BUFFER, 0, error);
      }
      if (n < 0) {
        relay_ok = false;
        break;
      }
      if (n == 0)
        break;
      progress = true;
      if (::send(local, buf, static_cast<size_t>(n), 0) <= 0) {
        relay_ok = false;
        break;
      }
    }
    if (!relay_ok)
      break;
    // 本地 → 隧道：非阻塞查一次
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(local, &rfds);
    timeval tv{0, 0};
    int rc = ::select(local + 1, &rfds, nullptr, nullptr, &tv);
    if (rc < 0)
      break;
    if (FD_ISSET(local, &rfds)) {
      int n = ::recv(local, buf, RELAY_BUFFER, 0);
      if (n <= 0)
        break;
      progress = true;
      bool wok = tls ? tls->write_all(buf, static_cast<size_t>(n), error)
                     : conn->write_all(buf, static_cast<size_t>(n), error);
      if (!wok)
        break;
    }
    // 两边暂无数据：阻塞等隧道一小段，避免空转
    if (!progress) {
      if (tls) {
        int n = tls->read_some(buf, RELAY_BUFFER, IDLE_WAIT_MS, error);
        if (n < 0)
          break;
        if (n > 0 && ::send(local, buf, static_cast<size_t>(n), 0) <= 0)
          break;
      } else {
        conn->wait_readable(IDLE_WAIT_MS);
      }
    }
  }
  shutdown(local, SHUT_RDWR);
  ::close(local);
  conn->close();
  nps_free(buf);
  return true;
}

bool NpsClient::dial_local_(const std::string &host, uint32_t timeout_ms,
                            int &out_fd, int &out_errno,
                            std::string &error) {
  std::string h(host);
  std::string port = "80";
  size_t colon = h.rfind(':');
  if (colon != std::string::npos) {
    port = h.substr(colon + 1);
    h = h.substr(0, colon);
  }
  if (h.empty()) {
    error = "本地目标地址为空";
    out_errno = EINVAL;
    return false;
  }
  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  addrinfo *list = nullptr;
  int rc = getaddrinfo(h.c_str(), port.c_str(), &hints, &list);
  if (rc != 0 || list == nullptr) {
    error = "解析本地目标失败: " + host;
    out_errno = EHOSTUNREACH;
    return false;
  }
  for (auto *p = list; p != nullptr; p = p->ai_next) {
    int fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd < 0)
      continue;
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    rc = ::connect(fd, p->ai_addr, p->ai_addrlen);
    bool ok = rc == 0;
    if (rc < 0 && errno == EINPROGRESS) {
      fd_set wfds;
      FD_ZERO(&wfds);
      FD_SET(fd, &wfds);
      timeval tv{static_cast<long>(timeout_ms / 1000),
                 static_cast<long>((timeout_ms % 1000) * 1000)};
      rc = ::select(fd + 1, nullptr, &wfds, nullptr, &tv);
      if (rc > 0) {
        int e = 0;
        socklen_t n = sizeof(e);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &n) == 0 && e == 0)
          ok = true;
        else {
          out_errno = e != 0 ? e : ECONNREFUSED;
        }
      } else if (rc == 0) {
        out_errno = ETIMEDOUT;
      } else {
        out_errno = errno;
      }
    } else if (rc < 0) {
      out_errno = errno;
    }
    if (ok) {
      fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
      int one = 1;
      setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
      freeaddrinfo(list);
      out_fd = fd;
      out_errno = 0;
      return true;
    }
    ::close(fd);
  }
  freeaddrinfo(list);
  error = "连接本地目标失败: " + host + " (errno=" +
          std::to_string(out_errno) + ")";
  return false;
}

void NpsClient::control_loop_(std::atomic<bool> &stop,
                              std::atomic<bool> &reload) {
  std::string error;
  while (!stop.load() && !reload.load() && mux_ != nullptr && mux_->running()) {
    if (!signal_->wait_readable(250))
      continue;
    uint8_t flag[4];
    if (!signal_->read_all(flag, sizeof(flag), error))
      break;
    std::vector<uint8_t> payload;
    if (!read_len32_payload_(payload, error))
      break;
    ESP_LOGV(TAG, "main 信令 flag=%.4s len=%u",
             reinterpret_cast<const char *>(flag),
             static_cast<unsigned>(payload.size()));
  }
  if (!error.empty())
    ESP_LOGW(TAG, "main 信令结束: %s", error.c_str());
}

bool NpsClient::run(const std::function<NpsConfig()> &config_provider,
                    std::atomic<bool> &stop, std::atomic<bool> &reload,
                    std::string &error) {
  connected_ = false;
  uint8_t probe_proto = 0;  // 无响应降级探测尚未完成的协议版本
  while (true) {
    // 每次循环重新拉取最新配置；先消费 reload
    bool reloaded = reload.exchange(false);
    if (reloaded) {
      ESP_LOGI(TAG, "配置已更新，重新连接");
      probe_proto = 0;  // 配置更新后重新按配置值探测
    }
    config_ = config_provider();
    use_psram_ = config_.use_psram;
    uint8_t proto = config_.proto_version > 0 ? config_.proto_version : 9;
    if (probe_proto != 0) {
      proto = probe_proto;  // 继续上一次未完成的降级探测
    } else if (last_server_ != config_.server) {
      last_server_ = config_.server;  // 服务器变化：重新探测协议版本
      last_proto_ = 0;
    } else if (!reloaded && last_proto_ > 0) {
      proto = last_proto_;  // 同一服务器：沿用已协商版本
    }
    if (stop.load()) {
      error = "配置切换或停止";
      return false;
    }
    connected_ = false;
    connected_since_us_.store(0);
    connection_epoch_.fetch_add(1);
    uuid_.clear();
    signal_.reset();
    if (mux_) {
      mux_->close();
      mux_.reset();
    }
    if (transport_)
      transport_.reset();

    transport_ = std::make_unique<NpsTransport>();
    bool use_tls = strcmp(config_.mode, "tls") == 0;
    char addr[192];
    snprintf(addr, sizeof(addr), "%s:%u", config_.server,
             use_tls ? config_.tls_port : config_.tcp_port);
    if (!transport_->connect(addr, use_tls, config_.connect_timeout_s, error)) {
      ESP_LOGW(TAG, "%s", error.c_str());
      for (uint32_t i = 0; i < config_.reconnect_delay_s * 10U && !stop.load() && !reload.load();
           i++)
        vTaskDelay(pdMS_TO_TICKS(100));
      continue;
    }
    size_t rx_bytes = 0;
    uint8_t attempted = proto;
    if (!handshake_(attempted, rx_bytes, error)) {
      bool no_response = (rx_bytes == 0);
      if (no_response && attempted > 5) {
        ESP_LOGW(TAG,
                 "握手失败且服务端未返回任何数据（可能是协议版本不匹配），"
                 "尝试 proto=%u",
                 static_cast<unsigned>(attempted - 1));
        proto = attempted - 1;
        probe_proto = proto;
        transport_->close();
        transport_.reset();
        continue;  // 立即用更低版本重连
      }
      if (no_response && attempted <= 5) {
        // 降到最低仍被拒：复位到配置值，走正常重连延时
        proto = config_.proto_version > 0 ? config_.proto_version : 9;
        probe_proto = 0;
      }
      ESP_LOGW(TAG, "握手失败 (proto=%u): %s", static_cast<unsigned>(attempted),
               error.c_str());
      transport_->close();
      transport_.reset();
      for (uint32_t i = 0; i < config_.reconnect_delay_s * 10U && !stop.load() && !reload.load();
           i++)
        vTaskDelay(pdMS_TO_TICKS(100));
      continue;
    }
    last_proto_ = proto;
    probe_proto = 0;
    if (!send_chan_(proto, error)) {
      ESP_LOGW(TAG, "chan 发送失败 (proto=%u): %s",
               static_cast<unsigned>(proto), error.c_str());
      transport_->close();
      transport_.reset();
      for (uint32_t i = 0; i < config_.reconnect_delay_s * 10U && !stop.load() && !reload.load();
           i++)
        vTaskDelay(pdMS_TO_TICKS(100));
      continue;
    }
    if (!open_main_(proto, error)) {
      ESP_LOGW(TAG, "main 建立失败 (proto=%u): %s",
               static_cast<unsigned>(proto), error.c_str());
      if (mux_) {
        mux_->close();
        mux_.reset();
      }
      signal_.reset();
      if (transport_)
        transport_.reset();
      for (uint32_t i = 0; i < config_.reconnect_delay_s * 10U && !stop.load() && !reload.load();
           i++)
        vTaskDelay(pdMS_TO_TICKS(100));
      continue;
    }
    ESP_LOGI(TAG, "nps 连接成功，等待隧道会话");
    control_loop_(stop, reload);
    connected_ = false;
    connected_since_us_.store(0);
    connection_epoch_.fetch_add(1);
    if (mux_) {
      mux_->close();
      mux_.reset();
    }
    signal_.reset();
    transport_.reset();
    if (stop.load())
      break;
    if (reload.load())
      continue;  // 配置已更新：跳过重连等待，立即按新配置重连
    ESP_LOGW(TAG, "会话断开，%u 秒后重连",
             static_cast<unsigned>(config_.reconnect_delay_s));
    for (uint32_t i = 0; i < config_.reconnect_delay_s * 10U && !stop.load() && !reload.load();
         i++)
      vTaskDelay(pdMS_TO_TICKS(100));
  }
  return true;
}

}  // namespace esphome::nps
