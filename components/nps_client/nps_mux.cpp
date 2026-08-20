#include "nps_mux.h"

#include <algorithm>
#include <cstring>

#include "esp_timer.h"
#include "esphome/core/log.h"
#include "nps_crypto.h"

namespace esphome::nps {
static const char *const TAG = "nps.mux";

#if defined(CONFIG_IDF_TARGET_ARCH_RISCV)
static constexpr uint32_t MUX_READER_STACK = 6144;
static constexpr uint32_t MUX_PING_STACK = 2560;
#else
static constexpr uint32_t MUX_READER_STACK = 8192;
static constexpr uint32_t MUX_PING_STACK = 4096;
#endif

static uint16_t read_u16_(const uint8_t *p) {  // Go: binary.LittleEndian
  return p[0] | (static_cast<uint16_t>(p[1]) << 8);
}
static uint32_t read_u32_(const uint8_t *p) {  // Go: binary.LittleEndian
  return p[0] | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}
static uint64_t read_u64_le_(const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 7; i >= 0; i--)
    v = (v << 8) | p[i];
  return v;
}
static void write_u16_(uint8_t *p, uint16_t v) {  // Go: binary.LittleEndian
  p[0] = static_cast<uint8_t>(v & 0xFF);
  p[1] = static_cast<uint8_t>(v >> 8);
}
static void write_u32_(uint8_t *p, uint32_t v) {  // Go: binary.LittleEndian
  p[0] = static_cast<uint8_t>(v & 0xFF);
  p[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
  p[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
  p[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}
static void write_u64_(uint8_t *p, uint64_t v) {
  for (int i = 7; i >= 0; i--) {
    p[i] = static_cast<uint8_t>(v & 0xFF);
    v >>= 8;
  }
}
static void write_u64_le_(uint8_t *p, uint64_t v) {
  for (int i = 0; i < 8; i++) {
    p[i] = static_cast<uint8_t>(v & 0xFF);
    v >>= 8;
  }
}

// 窗口打包：bit63=wait，bits32-62=maxSize，bits0-31=done
static uint64_t pack_window_(uint32_t max_size, uint32_t done, bool wait) {
  uint64_t v = static_cast<uint64_t>(max_size & 0x7FFFFFFF) << 32;
  v |= static_cast<uint64_t>(done & 0x7FFFFFFF);
  if (wait)
    v |= UINT64_C(1) << 63;
  return v;
}

static uint64_t pack_send_ok_(uint32_t max_size, uint32_t read) {
  return pack_window_(max_size, read, false);
}

NpsMuxConn::NpsMuxConn(std::shared_ptr<NpsMux> mux, int32_t id,
                       NpsPsRamResource *psram_resource)
    : mux_(mux), id_(id), receive_buffer_(psram_resource) {
  send_window_max_ = mux->initial_window();
  mutex_ = xSemaphoreCreateMutex();
  data_ready_ = xSemaphoreCreateBinary();
  send_ready_ = xSemaphoreCreateBinary();
}

NpsMuxConn::~NpsMuxConn() {
  close();
  if (mutex_)
    vSemaphoreDelete(mutex_);
  if (data_ready_)
    vSemaphoreDelete(data_ready_);
  if (send_ready_)
    vSemaphoreDelete(send_ready_);
}

void NpsMuxConn::receive_(const uint8_t *payload, size_t length) {
  xSemaphoreTake(mutex_, portMAX_DELAY);
  if (length > 0) {
    if (receive_offset_ > 0) {
      receive_buffer_.erase(receive_buffer_.begin(),
                            receive_buffer_.begin() + receive_offset_);
      receive_offset_ = 0;
    }
    receive_buffer_.insert(receive_buffer_.end(), payload, payload + length);
  }
  xSemaphoreGive(mutex_);
  xSemaphoreGive(data_ready_);
}

void NpsMuxConn::apply_window_update_(uint64_t packed) {
  uint32_t max_size =
      static_cast<uint32_t>((packed >> 32) & 0x7FFFFFFF);
  uint32_t read = static_cast<uint32_t>(packed & 0x7FFFFFFF);
  bool woke = false;
  xSemaphoreTake(mutex_, portMAX_DELAY);
  if (read > send_sent_) {
    // 服务端偶发 read 计数超前（会话重建或对端内部竞争），钳制后按 0 处理，
    // 下一次窗口更新会重新对齐，不必因此断掉整个会话。
    ESP_LOGW(TAG, "窗口更新 read=%u > sent=%u (id=%d)，已钳制",
             static_cast<unsigned>(read),
             static_cast<unsigned>(send_sent_),
             static_cast<int>(id_));
    read = send_sent_;
  }
  uint32_t outstanding = (send_sent_ - read) & 0x7FFFFFFF;
  send_window_max_ = max_size;
  send_sent_ = outstanding;
  uint32_t remain = send_window_max_ > send_sent_
                        ? send_window_max_ - send_sent_
                        : 0;
  woke = remain > 0;
  xSemaphoreGive(mutex_);
  if (woke)
    xSemaphoreGive(send_ready_);
}

void NpsMuxConn::remote_close_() {
  xSemaphoreTake(mutex_, portMAX_DELAY);
  remote_closed_ = true;
  xSemaphoreGive(mutex_);
  xSemaphoreGive(data_ready_);
}

void NpsMuxConn::remote_write_close_() {
  xSemaphoreTake(mutex_, portMAX_DELAY);
  remote_write_closed_ = true;
  xSemaphoreGive(mutex_);
  xSemaphoreGive(data_ready_);
}

void NpsMuxConn::fail_(const std::string &error) {
  xSemaphoreTake(mutex_, portMAX_DELAY);
  error_ = error;
  remote_closed_ = true;
  xSemaphoreGive(mutex_);
  xSemaphoreGive(data_ready_);
  xSemaphoreGive(send_ready_);
}

bool NpsMuxConn::wait_readable(uint32_t timeout_ms) {
  xSemaphoreTake(mutex_, portMAX_DELAY);
  bool ready = receive_offset_ < receive_buffer_.size() || remote_closed_ ||
               remote_write_closed_ || !error_.empty();
  xSemaphoreGive(mutex_);
  if (ready)
    return true;
  return xSemaphoreTake(data_ready_, pdMS_TO_TICKS(timeout_ms)) == pdTRUE;
}

int NpsMuxConn::read_some(uint8_t *data, size_t length, uint32_t timeout_ms,
                          std::string &error) {
  if (length == 0)
    return 0;
  while (true) {
    xSemaphoreTake(mutex_, portMAX_DELAY);
    size_t available = receive_buffer_.size() - receive_offset_;
    if (available > 0) {
      size_t count = std::min(length, available);
      memcpy(data, receive_buffer_.data() + receive_offset_, count);
      receive_offset_ += count;
      bool drained = receive_offset_ == receive_buffer_.size();
      if (drained) {
        receive_buffer_.clear();
        receive_offset_ = 0;
        // 突发积压后回收过大的容量，避免大窗口带来的缓冲长期驻留
        if (receive_buffer_.capacity() > 96 * 1024)
          receive_buffer_.shrink_to_fit();
      }
      consumed_since_update_ += static_cast<uint32_t>(count);
      bool send_update =
          consumed_since_update_ >= mux_->initial_window() ||
          (drained && consumed_since_update_ > 0);
      xSemaphoreGive(mutex_);
      if (send_update)
        send_pending_window_update_();
      return static_cast<int>(count);
    }
    bool closed = remote_closed_;
    bool write_closed = remote_write_closed_;
    std::string stream_error = error_;
    xSemaphoreGive(mutex_);
    if (!stream_error.empty()) {
      error = stream_error;
      return -1;
    }
    if (closed || write_closed) {
      error = "mux 逻辑流已关闭";
      return -1;
    }
    if (!mux_ || !mux_->running()) {
      error = "mux 会话已关闭";
      return -1;
    }
    if (xSemaphoreTake(data_ready_,
                       timeout_ms == UINT32_MAX ? portMAX_DELAY
                                                : pdMS_TO_TICKS(timeout_ms)) !=
        pdTRUE)
      return 0;
  }
}

bool NpsMuxConn::read_all(uint8_t *data, size_t length, std::string &error) {
  size_t offset = 0;
  while (offset < length) {
    int n = read_some(data + offset, length - offset, UINT32_MAX, error);
    if (n <= 0)
      return false;
    offset += static_cast<size_t>(n);
  }
  return true;
}

void NpsMuxConn::send_pending_window_update_() {
  if (!mux_ || !mux_->running())
    return;
  xSemaphoreTake(mutex_, portMAX_DELAY);
  uint32_t consumed = consumed_since_update_;
  consumed_since_update_ = 0;
  xSemaphoreGive(mutex_);
  if (consumed == 0)
    return;
  std::string ignored;
  mux_->send_window_update_(id_, consumed, ignored);
}

bool NpsMuxConn::write_all(const uint8_t *data, size_t length,
                           std::string &error) {
  size_t offset = 0;
  while (offset < length) {
    xSemaphoreTake(mutex_, portMAX_DELAY);
    uint32_t remain = send_window_max_ > send_sent_
                          ? send_window_max_ - send_sent_
                          : 0;
    bool closed = remote_closed_ || local_closed_;
    std::string stream_error = error_;
    xSemaphoreGive(mutex_);
    if (!stream_error.empty()) {
      error = stream_error;
      return false;
    }
    if (closed || !mux_ || !mux_->running()) {
      error = "mux 逻辑流不可写";
      return false;
    }
    if (remain == 0) {
      if (xSemaphoreTake(send_ready_, pdMS_TO_TICKS(mux_->ping_timeout_s() * 1000U)) !=
          pdTRUE) {
        error = "mux 发送窗口等待超时";
        return false;
      }
      continue;
    }
    size_t left = length - offset;
    uint32_t count = static_cast<uint32_t>(
        std::min<uint64_t>(std::min<uint64_t>(left, NpsMux::SEGMENT_SIZE),
                           remain));
    bool part = count < left;
    uint8_t flag = part ? NpsMux::FLAG_NEW_MSG_PART : NpsMux::FLAG_NEW_MSG;
    if (!mux_->send_frame_(flag, id_, data + offset, count, 0, false, error))
      return false;
    xSemaphoreTake(mutex_, portMAX_DELAY);
    send_sent_ = (send_sent_ + count) & 0x7FFFFFFF;
    xSemaphoreGive(mutex_);
    offset += count;
  }
  return true;
}

void NpsMuxConn::close() {
  if (mutex_ == nullptr)
    return;
  xSemaphoreTake(mutex_, portMAX_DELAY);
  bool send_close = !local_closed_ && !remote_closed_;
  local_closed_ = true;
  xSemaphoreGive(mutex_);
  if (send_close && mux_ != nullptr && mux_->running()) {
    std::string ignored;
    mux_->send_frame_(NpsMux::FLAG_CONN_CLOSE, id_, nullptr, 0, 0, false,
                      ignored);
    mux_->remove_stream_(id_);
  }
}

NpsMux::NpsMux() {
  streams_mutex_ = xSemaphoreCreateMutex();
  write_mutex_ = xSemaphoreCreateMutex();
  accept_mutex_ = xSemaphoreCreateMutex();
  accept_ready_ = xSemaphoreCreateBinary();
  reader_stopped_ = xSemaphoreCreateBinary();
  ping_stopped_ = xSemaphoreCreateBinary();
}

NpsMux::~NpsMux() {
  close();
  if (streams_mutex_)
    vSemaphoreDelete(streams_mutex_);
  if (write_mutex_)
    vSemaphoreDelete(write_mutex_);
  if (accept_mutex_)
    vSemaphoreDelete(accept_mutex_);
  if (accept_ready_)
    vSemaphoreDelete(accept_ready_);
  if (reader_stopped_)
    vSemaphoreDelete(reader_stopped_);
  if (ping_stopped_)
    vSemaphoreDelete(ping_stopped_);
}

bool NpsMux::start(std::unique_ptr<NpsTransport> transport, bool use_psram,
                   uint16_t ping_timeout_s, std::string &error) {
  use_psram_ = use_psram;
  psram_resource_.set_use_psram(use_psram);
  // PSRAM 可用时放大接收窗口，提高高 RTT 链路的吞吐（缓冲驻留在 PSRAM）
  initial_window_ = use_psram ? 262144 : DEFAULT_INITIAL_WINDOW;
  if (!streams_mutex_ || !write_mutex_ || !accept_mutex_ || !accept_ready_ ||
      !reader_stopped_ || !ping_stopped_) {
    error = "创建 mux 同步对象失败";
    return false;
  }
  transport_ = std::move(transport);
  running_ = true;
  ping_timeout_s_ = ping_timeout_s > 0 ? ping_timeout_s : 60;
  mark_alive_();
  if (xTaskCreate(reader_entry_, "nps_mux", MUX_READER_STACK, this, 5,
                  &reader_task_) != pdPASS) {
    running_ = false;
    transport_->close();
    transport_.reset();
    error = "创建 mux 接收任务失败";
    return false;
  }
  if (xTaskCreate(ping_entry_, "nps_mux_ping", MUX_PING_STACK, this, 3,
                  &ping_task_) != pdPASS) {
    running_ = false;
    transport_->close();
    error = "创建 mux 心跳任务失败";
    return false;
  }
  // 双方各发一次能力协商（capabilityCloseWrite=1）
  uint8_t hello[5];
  hello[0] = FLAG_PEER_HELLO;
  write_u32_(hello + 1, 1);
  if (!transport_->write_all(hello, sizeof(hello), error)) {
    running_ = false;
    transport_->close();
    return false;
  }
  ESP_LOGI(TAG, "mux started");
  return true;
}

bool NpsMux::send_frame_(uint8_t flag, int32_t id, const uint8_t *payload,
                         size_t payload_len, uint64_t window, bool has_window,
                         std::string &error) {
  if (!running_ || !transport_) {
    error = "mux 会话已关闭";
    return false;
  }
  uint8_t header[13];
  size_t header_len;
  header[0] = flag;
  write_u32_(header + 1, static_cast<uint32_t>(id));
  bool with_payload = flag == FLAG_PING || flag == FLAG_PING_RETURN ||
                      flag == FLAG_NEW_MSG || flag == FLAG_NEW_MSG_PART;
  if (has_window) {
    write_u64_le_(header + 5, window);  // Go: binary.LittleEndian
    header_len = 13;
  } else if (with_payload) {
    if (payload == nullptr || payload_len == 0 || payload_len > SEGMENT_SIZE) {
      error = "mux 数据帧参数非法";
      return false;
    }
    write_u16_(header + 5, static_cast<uint16_t>(payload_len));
    header_len = 7;
  } else {
    header_len = 5;
  }
  xSemaphoreTake(write_mutex_, portMAX_DELAY);
  bool ok = transport_->write_all(header, header_len, error);
  if (ok && with_payload)
    ok = transport_->write_all(payload, payload_len, error);
  xSemaphoreGive(write_mutex_);
  if (!ok) {
    running_ = false;
    fail_all_(error);
  }
  return ok;
}

bool NpsMux::send_window_update_(int32_t id, uint32_t consumed,
                                 std::string &error) {
  return send_frame_(FLAG_MSG_SEND_OK, id, nullptr, 0,
                     pack_send_ok_(initial_window_, consumed), true, error);
}

std::shared_ptr<NpsMuxConn> NpsMux::open_stream(std::string &error) {
  if (!running_) {
    error = "mux 未连接";
    return nullptr;
  }
  xSemaphoreTake(streams_mutex_, portMAX_DELAY);
  int32_t id = next_stream_id_;
  if (next_stream_id_ >= INT32_MAX - 2) {
    next_stream_id_ = -1;
    id = -1;
  }
  next_stream_id_ += 2;
  auto stream = std::shared_ptr<NpsMuxConn>(
      new NpsMuxConn(shared_from_this(), id, &psram_resource_));
  if (!stream->valid_()) {
    xSemaphoreGive(streams_mutex_);
    error = "创建 mux 逻辑流同步对象失败";
    return nullptr;
  }
  streams_[id] = stream;
  xSemaphoreGive(streams_mutex_);

  if (!send_frame_(FLAG_NEW_CONN, id, nullptr, 0, 0, false, error)) {
    remove_stream_(id);
    return nullptr;
  }
  // 等待 muxNewConnOk / muxNewConnFail
  if (!stream->wait_readable(10000)) {
    remove_stream_(id);
    error = "mux 新连接响应超时";
    return nullptr;
  }
  xSemaphoreTake(stream->mutex_, portMAX_DELAY);
  std::string stream_error = stream->error_;
  xSemaphoreGive(stream->mutex_);
  if (!stream_error.empty()) {
    remove_stream_(id);
    error = "mux 新连接被拒绝: " + stream_error;
    return nullptr;
  }
  return stream;
}

std::shared_ptr<NpsMuxConn> NpsMux::accept_stream(uint32_t timeout_ms,
                                                  std::string &error) {
  if (!running_) {
    error = "mux 未连接";
    return nullptr;
  }
  xSemaphoreTake(accept_mutex_, portMAX_DELAY);
  if (!accept_queue_.empty()) {
    auto conn = accept_queue_.front();
    accept_queue_.pop_front();
    xSemaphoreGive(accept_mutex_);
    return conn;
  }
  xSemaphoreGive(accept_mutex_);
  if (xSemaphoreTake(accept_ready_, pdMS_TO_TICKS(timeout_ms)) != pdTRUE) {
    if (!running_)
      error = "mux 已关闭";
    else
      error = "accept 超时";
    return nullptr;
  }
  xSemaphoreTake(accept_mutex_, portMAX_DELAY);
  std::shared_ptr<NpsMuxConn> conn;
  if (!accept_queue_.empty()) {
    conn = accept_queue_.front();
    accept_queue_.pop_front();
  }
  xSemaphoreGive(accept_mutex_);
  return conn;
}

std::shared_ptr<NpsMuxConn> NpsMux::find_stream_(int32_t id) {
  xSemaphoreTake(streams_mutex_, portMAX_DELAY);
  auto it = streams_.find(id);
  auto stream = it == streams_.end() ? nullptr : it->second;
  xSemaphoreGive(streams_mutex_);
  return stream;
}

void NpsMux::remove_stream_(int32_t id) {
  xSemaphoreTake(streams_mutex_, portMAX_DELAY);
  streams_.erase(id);
  xSemaphoreGive(streams_mutex_);
}

void NpsMux::fail_all_(const std::string &error) {
  xSemaphoreTake(streams_mutex_, portMAX_DELAY);
  auto streams = streams_;
  xSemaphoreGive(streams_mutex_);
  for (auto &entry : streams)
    entry.second->fail_(error);
}

void NpsMux::reader_entry_(void *arg) {
  static_cast<NpsMux *>(arg)->reader_();
  vTaskDelete(nullptr);
}

void NpsMux::reader_() {
  std::string error;
  while (running_) {
    uint8_t header[13];
    if (!transport_->read_all(header, 5, error))
      break;
    uint8_t flag = header[0];
    int32_t id = static_cast<int32_t>(read_u32_(header + 1));
    uint16_t length = 0;
    uint64_t window = 0;
    bool has_payload = flag == FLAG_PING || flag == FLAG_PING_RETURN ||
                       flag == FLAG_NEW_MSG || flag == FLAG_NEW_MSG_PART;
    if (has_payload) {
      if (!transport_->read_all(header + 5, 2, error))
        break;
      length = read_u16_(header + 5);
      if (length == 0 || length > SEGMENT_SIZE) {
        error = "mux 数据帧长度非法";
        break;
      }
    } else if (flag == FLAG_MSG_SEND_OK) {
      if (!transport_->read_all(header + 5, 8, error))
        break;
      window = read_u64_le_(header + 5);
    }
    mark_alive_();

    switch (flag) {
      case FLAG_NEW_CONN: {
        auto conn = std::shared_ptr<NpsMuxConn>(
            new NpsMuxConn(shared_from_this(), id, &psram_resource_));
        if (!conn->valid_()) {
          std::string ignored;
          send_frame_(FLAG_NEW_CONN_FAIL, id, nullptr, 0, 0, false, ignored);
          break;
        }
        xSemaphoreTake(streams_mutex_, portMAX_DELAY);
        streams_[id] = conn;
        xSemaphoreGive(streams_mutex_);
        xSemaphoreTake(accept_mutex_, portMAX_DELAY);
        accept_queue_.push_back(conn);
        xSemaphoreGive(accept_mutex_);
        xSemaphoreGive(accept_ready_);
        std::string ignored;
        send_frame_(FLAG_NEW_CONN_OK, id, nullptr, 0, 0, false, ignored);
        break;
      }
      case FLAG_NEW_CONN_OK: {
        auto conn = find_stream_(id);
        if (conn)
          conn->receive_(nullptr, 0);  // 仅唤醒 open_stream 的等待
        break;
      }
      case FLAG_NEW_CONN_FAIL: {
        auto conn = find_stream_(id);
        if (conn)
          conn->fail_("对端拒绝新连接");
        break;
      }
      case FLAG_NEW_MSG:
      case FLAG_NEW_MSG_PART: {
        uint8_t *payload =
            length > 0 ? nps_alloc(length, use_psram_) : nullptr;
        if (length > 0 && payload == nullptr) {
          error = "mux 数据 OOM";
          break;
        }
        if (!transport_->read_all(payload, length, error)) {
          nps_free(payload);
          break;
        }
        auto conn = find_stream_(id);
        if (conn)
          conn->receive_(payload, length);
        else {
          std::string ignored;
          send_frame_(FLAG_CONN_CLOSE, id, nullptr, 0, 0, false, ignored);
        }
        nps_free(payload);
        break;
      }
      case FLAG_MSG_SEND_OK: {
        auto conn = find_stream_(id);
        if (conn)
          conn->apply_window_update_(window);
        break;
      }
      case FLAG_PING: {
        uint8_t *payload = nps_alloc(length, use_psram_);
        if (payload == nullptr) {
          error = "mux ping OOM";
          break;
        }
        if (!transport_->read_all(payload, length, error)) {
          nps_free(payload);
          break;
        }
        std::string ignored;
        send_frame_(FLAG_PING_RETURN, PING_STREAM_ID, payload, length, 0, false,
                    ignored);
        nps_free(payload);
        break;
      }
      case FLAG_PING_RETURN: {
        uint8_t *payload = nps_alloc(length, use_psram_);
        if (payload == nullptr) {
          error = "mux ping OOM";
          break;
        }
        if (!transport_->read_all(payload, length, error)) {
          nps_free(payload);
          break;
        }
        nps_free(payload);
        break;
      }
      case FLAG_PEER_HELLO:
        break;  // 能力位在 id 中，暂不需要使用
      case FLAG_CONN_CLOSE: {
        auto conn = find_stream_(id);
        if (conn) {
          conn->remote_close_();
          remove_stream_(id);
        }
        break;
      }
      case FLAG_CONN_CLOSE_WRITE: {
        auto conn = find_stream_(id);
        if (conn)
          conn->remote_write_close_();
        break;
      }
      default:
        ESP_LOGW(TAG, "未知 mux flag %u", static_cast<unsigned>(flag));
        break;
    }
  }
  if (error.empty())
    error = "mux 会话结束";
  ESP_LOGW(TAG, "%s", error.c_str());
  running_ = false;
  fail_all_(error);
  if (transport_)
    transport_->close();
  xSemaphoreGive(reader_stopped_);
  reader_task_ = nullptr;
  // 唤醒所有 accept 等待者
  xSemaphoreGive(accept_ready_);
}

void NpsMux::ping_entry_(void *arg) {
  static_cast<NpsMux *>(arg)->ping_();
  vTaskDelete(nullptr);
}

void NpsMux::ping_() {
  uint32_t ping_interval_s = 5;
  while (running_) {
    for (uint32_t elapsed = 0; elapsed < ping_interval_s * 10U && running_;
         elapsed++)
      vTaskDelay(pdMS_TO_TICKS(100));
    if (!running_)
      break;
    int64_t last = last_frame_us_.load();
    int64_t now = esp_timer_get_time();
    if (last > 0 && (now - last) / 1000000 >= static_cast<int64_t>(ping_timeout_s_)) {
      ESP_LOGW(TAG, "mux ping 超时，会话关闭");
      running_ = false;
      if (transport_)
        transport_->close();
      fail_all_("mux ping 超时");
      break;
    }
    // 有流量时推迟 ping，避免与数据帧争用带宽
    if (now - last < static_cast<int64_t>(ping_interval_s) * 1000000)
      continue;
    uint8_t payload[24];
    write_u64_(payload, static_cast<uint64_t>(now * 1000));
    size_t pad = 0;
    if ((now & 1) == 0)
      pad = 1 + (static_cast<size_t>(now) % 16);
    if (pad > 0)
      nps_random_bytes(payload + 8, pad);
    std::string error;
    if (!send_frame_(FLAG_PING, PING_STREAM_ID, payload, 8 + pad, 0, false,
                     error))
      break;
  }
  xSemaphoreGive(ping_stopped_);
  ping_task_ = nullptr;
}

void NpsMux::close() {
  bool was_running = running_.exchange(false);
  if (transport_)
    transport_->close();
  if (reader_task_ != nullptr && xTaskGetCurrentTaskHandle() != reader_task_)
    xSemaphoreTake(reader_stopped_, pdMS_TO_TICKS(2000));
  if (ping_task_ != nullptr && xTaskGetCurrentTaskHandle() != ping_task_)
    xSemaphoreTake(ping_stopped_, pdMS_TO_TICKS(2000));
  if (was_running)
    fail_all_("mux 会话已关闭");
}

}  // namespace esphome::nps
