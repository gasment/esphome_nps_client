#include "nps_client.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <sys/poll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "esphome/core/log.h"
#include "nps_crypto.h"
#include "nps_json.h"
#include "nps_mem.h"
#include "nps_tls_stream.h"

namespace esphome::nps_origin {
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

// 旧版认证（ehang-io/nps）：
// "TST" + len32(核心版本) + len32(版本)
//   -> 读 32 字节 md5(核心版本)，校验
//   -> 写 md5(vkey) hex（32 字节）
//   -> 读 "sucs"/"vkey"
//   -> 写工作类型（"main"/"chan"）
std::unique_ptr<NpsTransport> NpsClient::legacy_connect_(
    const char *work_type, std::string &error) {
  char addr[192];
  snprintf(addr, sizeof(addr), "%s:%u", config_.server,
           static_cast<unsigned>(config_.tcp_port));

  // 候选核心版本：最近成功值优先，其次配置值，再按基准次版本号自动向两侧
  // 遍历（0.26.0 → 0.27.0/0.25.0 → 0.28.0/0.24.0 ...）。
  // 服务端升级导致 GetVersion() 变化时，仅需一次重连即可自动匹配。
  std::vector<std::string> candidates;
  auto push_unique = [&candidates](const std::string &v) {
    if (v.empty())
      return;
    for (const auto &c : candidates)
      if (c == v)
        return;
    candidates.push_back(v);
  };
  push_unique(effective_legacy_version_);
  push_unique(config_.legacy_version);
  // 基准次版本号：优先最近成功值，其次配置值
  int base_minor = -1;
  const std::string &base =
      !effective_legacy_version_.empty() ? effective_legacy_version_
                                         : config_.legacy_version;
  unsigned a = 0, b = 0, c = 0;
  if (sscanf(base.c_str(), "%u.%u.%u", &a, &b, &c) == 3)
    base_minor = static_cast<int>(b);
  if (base_minor >= 0) {
    for (int step = 0; step <= 60 && candidates.size() < 50; step++) {
      if (step == 0) {
        push_unique("0." + std::to_string(base_minor) + ".0");
      } else {
        int up = base_minor + step;
        int down = base_minor - step;
        if (up <= 99)
          push_unique("0." + std::to_string(up) + ".0");
        if (down >= 0)
          push_unique("0." + std::to_string(down) + ".0");
      }
    }
  }

  for (const auto &ver : candidates) {
    auto t = std::make_unique<NpsTransport>();
    // TCP 连接失败视为网络问题，直接返回，不浪费候选探测
    if (!t->connect(addr, false, config_.connect_timeout_s, error))
      return nullptr;

    static const uint8_t kTst[3] = {'T', 'S', 'T'};
    if (!t->write_all(kTst, sizeof(kTst), error)) {
      t->close();
      return nullptr;
    }
    const uint8_t *ver_bytes =
        reinterpret_cast<const uint8_t *>(ver.data());
    size_t vlen = ver.size();
    std::vector<uint8_t> version_msg;
    nps_append_len32(version_msg, ver_bytes, vlen);
    nps_append_len32(version_msg, ver_bytes, vlen);
    if (!t->write_all(version_msg.data(), version_msg.size(), error)) {
      t->close();
      return nullptr;
    }

    // 版本不匹配时服务端直接关闭（无响应），读失败则换下一个候选
    uint8_t resp[32];
    std::string read_err;
    if (!t->read_all(resp, sizeof(resp), read_err)) {
      t->close();
      continue;
    }
    std::string expect = nps_md5_hex(ver.c_str());
    if (expect.size() != 32 || memcmp(resp, expect.data(), 32) != 0) {
      t->close();
      continue;
    }

    // 版本匹配成功，继续 vkey 认证
    std::string vk = nps_md5_hex(config_.vkey);
    if (vk.size() != 32 ||
        !t->write_all(reinterpret_cast<const uint8_t *>(vk.data()), vk.size(),
                      error)) {
      t->close();
      return nullptr;
    }
    uint8_t flag[4];
    if (!t->read_all(flag, sizeof(flag), error)) {
      t->close();
      return nullptr;
    }
    if (memcmp(flag, "vkey", 4) == 0) {
      error = "验证密钥错误";
      t->close();
      return nullptr;
    }
    if (memcmp(flag, "sucs", 4) != 0) {
      error = "服务端认证响应异常";
      t->close();
      return nullptr;
    }
    if (!t->write_all(reinterpret_cast<const uint8_t *>(work_type), 4, error)) {
      t->close();
      return nullptr;
    }
    effective_legacy_version_ = ver;
    ESP_LOGI(TAG, "旧版认证成功 type=%s core=%s", work_type, ver.c_str());
    return t;
  }
  error = "所有 legacy_version 候选均不匹配服务端核心版本";
  return nullptr;
}

bool NpsClient::read_len32_discard_(NpsTransport &t, std::string &error) {
  uint8_t lenbuf[4];
  if (!t.read_all(lenbuf, sizeof(lenbuf), error))
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
  return t.read_all(buf.data(), len, error);
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
  constexpr uint32_t IDLE_WAIT_MS = 20;
  constexpr int MAX_DRAIN_CHUNKS = 16;
  bool relay_ok = true;
  while (mux != nullptr && mux->running() && relay_ok) {
    bool progress = false;
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
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(local, &rfds);
    timeval tv{0, 0};
    int rc = select(local + 1, &rfds, nullptr, nullptr, &tv);
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
      rc = select(fd + 1, nullptr, &wfds, nullptr, &tv);
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

void NpsClient::control_loop_(NpsTransport &signal, std::atomic<bool> &stop,
                              std::atomic<bool> &reload) {
  std::string error;
  while (!stop.load() && !reload.load() && signal.connected()) {
    pollfd pfd{signal.fd(), POLLIN, 0};
    int rc = ::poll(&pfd, 1, 250);
    if (rc < 0)
      break;
    if (rc == 0)
      continue;  // 空闲轮询，让 stop/reload 及时生效
    uint8_t flag[4];
    if (!signal.read_all(flag, sizeof(flag), error))
      break;
    ESP_LOGV(TAG, "main 信令 flag=%.4s", reinterpret_cast<const char *>(flag));
    // 旧版仅 NEW_UDP_CONN("udpc") 带两个 len32 载荷；其它 flag 忽略（与旧客户端一致）
    if (memcmp(flag, "udpc", 4) == 0) {
      if (!read_len32_discard_(signal, error))
        break;
      if (!read_len32_discard_(signal, error))
        break;
    }
  }
  if (!error.empty())
    ESP_LOGW(TAG, "main 信令结束: %s", error.c_str());
}

bool NpsClient::run(const std::function<NpsConfig()> &config_provider,
                    std::atomic<bool> &stop, std::atomic<bool> &reload,
                    std::string &error) {
  connected_ = false;
  while (true) {
    bool reloaded = reload.exchange(false);
    config_ = config_provider();
    use_psram_ = config_.use_psram;
    if (last_server_ != config_.server) {
      if (!last_server_.empty())
        ESP_LOGI(TAG, "服务器地址变更，重置 legacy 版本探测");
      effective_legacy_version_.clear();  // 服务器变化：按配置重新探测
      last_server_ = config_.server;
    } else if (reloaded) {
      ESP_LOGI(TAG, "配置已更新，重新连接");
      effective_legacy_version_.clear();  // 配置更新（含 legacy_version）：重新探测
    }
    if (stop.load()) {
      error = "配置切换或停止";
      return false;
    }
    connected_ = false;
    connected_since_us_.store(0);
    connection_epoch_.fetch_add(1);
    if (mux_) {
      mux_->close();
      mux_.reset();
    }

    auto signal = legacy_connect_("main", error);
    if (!signal) {
      ESP_LOGW(TAG, "main 连接失败: %s", error.c_str());
      for (uint32_t i = 0; i < config_.reconnect_delay_s * 10U && !stop.load() && !reload.load();
           i++)
        vTaskDelay(pdMS_TO_TICKS(100));
      continue;
    }
    auto chan = legacy_connect_("chan", error);
    if (!chan) {
      ESP_LOGW(TAG, "chan 连接失败: %s", error.c_str());
      signal->close();
      for (uint32_t i = 0; i < config_.reconnect_delay_s * 10U && !stop.load() && !reload.load();
           i++)
        vTaskDelay(pdMS_TO_TICKS(100));
      continue;
    }
    mux_ = std::make_shared<NpsMux>();
    mux_->set_legacy_no_hello(true);
    if (!mux_->start(std::move(chan), use_psram_,
                     config_.disconnect_timeout_s, error)) {
      ESP_LOGW(TAG, "mux 启动失败: %s", error.c_str());
      signal->close();
      mux_.reset();
      for (uint32_t i = 0; i < config_.reconnect_delay_s * 10U && !stop.load() && !reload.load();
           i++)
        vTaskDelay(pdMS_TO_TICKS(100));
      continue;
    }
    if (xTaskCreate(accept_task_, "nps_accept", ACCEPT_STACK, this, 4, nullptr) !=
        pdPASS) {
      ESP_LOGW(TAG, "创建 accept 任务失败");
      mux_->close();
      mux_.reset();
      signal->close();
      for (uint32_t i = 0; i < config_.reconnect_delay_s * 10U && !stop.load() && !reload.load();
           i++)
        vTaskDelay(pdMS_TO_TICKS(100));
      continue;
    }
    connected_ = true;
    connected_since_us_.store(esp_timer_get_time());
    connection_epoch_.fetch_add(1);
    ESP_LOGI(TAG, "ehang-io 连接成功，等待隧道会话");
    control_loop_(*signal, stop, reload);
    connected_ = false;
    connected_since_us_.store(0);
    connection_epoch_.fetch_add(1);
    signal->close();
    if (mux_) {
      mux_->close();
      mux_.reset();
    }
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

}  // namespace esphome::nps_origin
