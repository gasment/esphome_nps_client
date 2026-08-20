#include "nps_component.h"

#include <cstring>

#include "esp_timer.h"
#include "esphome/core/log.h"
#include "nvs.h"

namespace esphome::nps_origin {
static const char *const TAG = "nps.component";

void NpsConfigApplyButton::press_action() { this->parent_->config_apply(); }

void NpsConfigSwitch::write_state(bool state) {
  this->publish_state(state);
}

void NpsConfigSwitch::setup() {
  optional<bool> initial = this->get_initial_state_with_restore_mode();
  if (initial.has_value()) {
    if (initial.value())
      this->turn_on();
    else
      this->turn_off();
  }
}

void NpsComponent::setup() {
  config_.enabled = true;
  mutex_ = xSemaphoreCreateMutex();
  if (mutex_ == nullptr) {
    ESP_LOGE(TAG, "创建配置互斥锁失败");
    return;
  }
  init_pending_();  // 静态 -> initial_value -> NVS slotA
  init_entities_();
  if (!config_valid_(config_)) {
    ESP_LOGW(TAG, "暂无有效连接配置（server/vkey/端口），等待实体配置后按应用按钮");
    return;
  }
  if (connection_enabled_)
    start_task_();
}

void NpsComponent::task_entry_(void *arg) {
  auto *self = static_cast<NpsComponent *>(arg);
  self->task_();
  vTaskDelete(nullptr);
}

void NpsComponent::task_() {
  std::string error;
  client_.run([this]() { return config_snapshot_(); }, stop_, reload_, error);
  if (!error.empty())
    ESP_LOGW(TAG, "nps 任务退出: %s", error.c_str());
  ESP_LOGD(TAG, "nps 客户端任务栈余量 %lu 字节",
           static_cast<unsigned long>(uxTaskGetStackHighWaterMark(nullptr)));
  task_handle_ = nullptr;  // 任务自删前清空句柄，便于重新启动
}

NpsConfig NpsComponent::config_snapshot_() {
  xSemaphoreTake(mutex_, portMAX_DELAY);
  NpsConfig c = config_;
  xSemaphoreGive(mutex_);
  return c;
}

bool NpsComponent::config_valid_(const NpsConfig &c) const {
  return c.server[0] != '\0' && c.vkey[0] != '\0' && c.tcp_port > 0 &&
         c.legacy_version[0] != '\0';
}

void NpsComponent::start_task_() {
  if (task_handle_ != nullptr)
    return;
  stop_ = false;  // 清除连接禁用/关机可能设置的停止标志
  if (xTaskCreate(task_entry_, "nps_client", task_stack_, this, 4,
                  &task_handle_) != pdPASS) {
    ESP_LOGE(TAG, "创建 nps 任务失败");
    return;
  }
  ESP_LOGI(TAG, "nps_client_origin 已启动，服务器 %s:%u（ehang-io 旧版协议）",
           config_.server, static_cast<unsigned>(config_.tcp_port));
}

void NpsComponent::load_nvs_(NpsConfig &c) {
  nvs_handle_t h;
  if (nvs_open("nps_ocfg", NVS_READONLY, &h) != ESP_OK)
    return;
  char key[16];
  auto load_str = [&](const char *suffix, char *dst, size_t size) {
    snprintf(key, sizeof(key), "%s", suffix);
    size_t len = 0;
    if (nvs_get_str(h, key, nullptr, &len) != ESP_OK || len == 0 || len > size)
      return;
    if (nvs_get_str(h, key, dst, &len) == ESP_OK && len > 0)
      dst[len - 1] = '\0';
  };
  load_str("server", c.server, sizeof(c.server));
  load_str("vkey", c.vkey, sizeof(c.vkey));
  load_str("legacy_version", c.legacy_version, sizeof(c.legacy_version));
  uint16_t v = 0;
  snprintf(key, sizeof(key), "tcp_port");
  if (nvs_get_u16(h, key, &v) == ESP_OK && v > 0)
    c.tcp_port = v;
  nvs_close(h);
}

void NpsComponent::init_pending_() {
  xSemaphoreTake(mutex_, portMAX_DELAY);
  // slotA 填充顺序：
  //   1) 编译期静态配置（已在 config_）
  //   2) 实体 initial_value 覆盖静态（首次启动初始化）
  //   3) NVS slotA（上次已应用）覆盖一切，保证重启后回到生效配置
  if (!initial_server_.empty() &&
      initial_server_.size() < sizeof(config_.server))
    snprintf(config_.server, sizeof(config_.server), "%s",
             initial_server_.c_str());
  if (!initial_vkey_.empty() &&
      initial_vkey_.size() < sizeof(config_.vkey))
    snprintf(config_.vkey, sizeof(config_.vkey), "%s",
             initial_vkey_.c_str());
  if (!initial_legacy_version_.empty() &&
      initial_legacy_version_.size() < sizeof(config_.legacy_version))
    snprintf(config_.legacy_version, sizeof(config_.legacy_version), "%s",
             initial_legacy_version_.c_str());
  uint16_t v = 0;
  if (parse_port_(initial_tcp_port_, v))
    config_.tcp_port = v;

  load_nvs_(config_);  // NVS slotA 优先

  // slotB 是纯内存草稿：默认等于生效配置（slotA）
  pending_ = config_;
  xSemaphoreGive(mutex_);
}

void NpsComponent::init_entities_() {
  syncing_entities_ = true;
  if (server_text_ != nullptr)
    server_text_->publish_state(pending_.server);
  if (tcp_port_text_ != nullptr)
    tcp_port_text_->publish_state(std::to_string(pending_.tcp_port));
  if (vkey_text_ != nullptr)
    vkey_text_->publish_state(pending_.vkey);
  if (legacy_version_text_ != nullptr)
    legacy_version_text_->publish_state(pending_.legacy_version);
  if (rollback_switch_ != nullptr)
    rollback_enabled_ = rollback_switch_->state;  // 开关已按 restore_mode 恢复
  if (connection_enabled_switch_ != nullptr)
    connection_enabled_ = connection_enabled_switch_->state;
  syncing_entities_ = false;

  if (server_text_ != nullptr)
    server_text_->add_on_state_callback(
        [this](const std::string &v) { this->on_server_changed(v); });
  if (tcp_port_text_ != nullptr)
    tcp_port_text_->add_on_state_callback(
        [this](const std::string &v) { this->on_tcp_port_changed(v); });
  if (vkey_text_ != nullptr)
    vkey_text_->add_on_state_callback(
        [this](const std::string &v) { this->on_vkey_changed(v); });
  if (legacy_version_text_ != nullptr)
    legacy_version_text_->add_on_state_callback(
        [this](const std::string &v) { this->on_legacy_version_changed(v); });
  if (rollback_switch_ != nullptr)
    rollback_switch_->add_on_state_callback(
        [this](bool v) { this->on_rollback_switch_changed(v); });
  if (connection_enabled_switch_ != nullptr)
    connection_enabled_switch_->add_on_state_callback(
        [this](bool v) { this->on_connection_enabled_changed(v); });
  if (config_apply_button_ != nullptr)
    config_apply_button_->add_on_press_callback(
        [this]() { this->config_apply(); });
}

void NpsComponent::persist_nvs_(const NpsConfig &c) {
  nvs_handle_t h;
  if (nvs_open("nps_ocfg", NVS_READWRITE, &h) != ESP_OK)
    return;
  char key[16];
  snprintf(key, sizeof(key), "server");
  nvs_set_str(h, key, c.server);
  snprintf(key, sizeof(key), "vkey");
  nvs_set_str(h, key, c.vkey);
  snprintf(key, sizeof(key), "legacy_version");
  nvs_set_str(h, key, c.legacy_version);
  snprintf(key, sizeof(key), "tcp_port");
  nvs_set_u16(h, key, c.tcp_port);
  esp_err_t err = nvs_commit(h);
  nvs_close(h);
  if (err != ESP_OK)
    ESP_LOGW(TAG, "NVS 保存 slotA 失败: %s", esp_err_to_name(err));
}

void NpsComponent::persist_slot_a_() {
  xSemaphoreTake(mutex_, portMAX_DELAY);
  NpsConfig c = config_;
  xSemaphoreGive(mutex_);
  persist_nvs_(c);
}

bool NpsComponent::parse_port_(const std::string &value, uint16_t &out) {
  if (value.empty() || value.size() > 5)
    return false;
  unsigned long v = 0;
  for (char ch : value) {
    if (ch < '0' || ch > '9')
      return false;
    v = v * 10 + static_cast<unsigned long>(ch - '0');
    if (v > 65535)
      return false;
  }
  if (v == 0)
    return false;
  out = static_cast<uint16_t>(v);
  return true;
}

void NpsComponent::on_server_changed(const std::string &value) {
  if (syncing_entities_ || applying_)
    return;
  if (value.empty() || value.size() >= sizeof(pending_.server)) {
    ESP_LOGW(TAG, "server 值无效，已忽略");
    return;
  }
  xSemaphoreTake(mutex_, portMAX_DELAY);
  snprintf(pending_.server, sizeof(pending_.server), "%s", value.c_str());
  xSemaphoreGive(mutex_);
  ESP_LOGI(TAG, "server 预配置已更新: %s", value.c_str());
}

void NpsComponent::on_tcp_port_changed(const std::string &value) {
  if (syncing_entities_ || applying_)
    return;
  uint16_t v;
  if (!parse_port_(value, v)) {
    ESP_LOGW(TAG, "tcp_port 值无效，已忽略: %s", value.c_str());
    return;
  }
  xSemaphoreTake(mutex_, portMAX_DELAY);
  pending_.tcp_port = v;
  xSemaphoreGive(mutex_);
  ESP_LOGI(TAG, "tcp_port 预配置已更新: %u", static_cast<unsigned>(v));
}

void NpsComponent::on_vkey_changed(const std::string &value) {
  if (syncing_entities_ || applying_)
    return;
  if (value.empty() || value.size() >= sizeof(pending_.vkey)) {
    ESP_LOGW(TAG, "client_vkey 值无效，已忽略");
    return;
  }
  xSemaphoreTake(mutex_, portMAX_DELAY);
  snprintf(pending_.vkey, sizeof(pending_.vkey), "%s", value.c_str());
  xSemaphoreGive(mutex_);
  ESP_LOGI(TAG, "client_vkey 预配置已更新");
}

void NpsComponent::on_legacy_version_changed(const std::string &value) {
  if (syncing_entities_ || applying_)
    return;
  if (value.empty() || value.size() >= sizeof(pending_.legacy_version)) {
    ESP_LOGW(TAG, "legacy_version 值无效，已忽略: %s", value.c_str());
    return;
  }
  xSemaphoreTake(mutex_, portMAX_DELAY);
  snprintf(pending_.legacy_version, sizeof(pending_.legacy_version), "%s",
           value.c_str());
  xSemaphoreGive(mutex_);
  ESP_LOGI(TAG, "legacy_version 预配置已更新: %s", value.c_str());
}

void NpsComponent::on_rollback_switch_changed(bool value) {
  if (syncing_entities_)
    return;
  rollback_enabled_ = value;  // publish_state 已按 restore_mode 持久化
  ESP_LOGI(TAG, "坏配置自动回滚: %s", value ? "开启" : "关闭");
}

void NpsComponent::on_connection_enabled_changed(bool value) {
  if (syncing_entities_)
    return;
  connection_enabled_ = value;
  if (value) {
    if (config_valid_(config_))
      start_task_();  // 开启：维持/恢复 nps 连接
    ESP_LOGI(TAG, "nps 连接已启用");
  } else {
    stop_connection_();  // 关闭：停止连接任务，配置读写与回滚不受影响
    ESP_LOGI(TAG, "nps 连接已禁用（配置读写与回滚仍可用）");
  }
}

void NpsComponent::stop_connection_() {
  stop_ = true;
  if (task_handle_ != nullptr)
    xTaskNotifyGive(task_handle_);
}

void NpsComponent::config_apply() {
  if (applying_) {
    ESP_LOGW(TAG, "正在应用预配置，请等待结果");
    return;
  }
  bool valid;
  xSemaphoreTake(mutex_, portMAX_DELAY);
  valid = pending_.server[0] != '\0' && pending_.vkey[0] != '\0' &&
          pending_.tcp_port > 0;
  if (valid) {
    slot_a_backup_ = config_;
    config_ = pending_;
  }
  xSemaphoreGive(mutex_);
  if (!valid) {
    ESP_LOGW(TAG, "预配置不完整或无效（server/vkey/端口），请检查实体");
    return;
  }
  if (!connection_enabled_) {
    // 连接禁用：直接固化新配置，不做连接验证
    persist_slot_a_();
    ESP_LOGI(TAG, "连接已禁用：新配置已直接固化到 slotA（未验证）");
    return;
  }
  apply_epoch_ = client_.connection_epoch();
  applying_ = true;
  apply_deadline_ms_ =
      static_cast<uint32_t>(esp_timer_get_time() / 1000) +
      (static_cast<uint32_t>(config_.connect_timeout_s) +
       static_cast<uint32_t>(config_.reconnect_delay_s) + 10U) *
          1000U;
  if (task_handle_ == nullptr)
    start_task_();  // 无静态配置：首次应用先启动任务，再验证连接
  reload_.store(true);
  ESP_LOGI(TAG, "开始应用预配置 server=%s port=%u（连接成功即固化 slotA）",
           config_.server, static_cast<unsigned>(config_.tcp_port));
}

void NpsComponent::rollback_() {
  std::string server, tcp, vkey, legacy;
  xSemaphoreTake(mutex_, portMAX_DELAY);
  config_ = slot_a_backup_;
  pending_ = slot_a_backup_;
  server = config_.server;
  tcp = std::to_string(config_.tcp_port);
  vkey = config_.vkey;
  legacy = config_.legacy_version;
  xSemaphoreGive(mutex_);
  syncing_entities_ = true;
  if (server_text_ != nullptr)
    server_text_->publish_state(server);
  if (tcp_port_text_ != nullptr)
    tcp_port_text_->publish_state(tcp);
  if (vkey_text_ != nullptr)
    vkey_text_->publish_state(vkey);
  if (legacy_version_text_ != nullptr)
    legacy_version_text_->publish_state(legacy);
  syncing_entities_ = false;
  reload_.store(true);
  ESP_LOGW(TAG, "预配置应用失败，已回滚到 slotA 有效配置");
}

void NpsComponent::loop() {
  if (applying_) {
    if (client_.connected() &&
        client_.connection_epoch() != apply_epoch_) {
      applying_ = false;
      persist_slot_a_();
      start_task_();  // 首次应用（无静态配置）时启动任务
      ESP_LOGI(TAG, "预配置连接成功，slotA 已同步");
    } else if (static_cast<uint32_t>(esp_timer_get_time() / 1000) >=
               apply_deadline_ms_) {
      applying_ = false;
      if (rollback_enabled_) {
        rollback_();
      } else {
        persist_slot_a_();  // 回滚关闭：把失败候选固化为 slotA，重启后继续使用
        ESP_LOGW(TAG, "预配置应用失败，回滚已关闭：已固化为 slotA，继续重试");
      }
    }
  }
  if (connection_status_ != nullptr) {
    bool now_connected = client_.connected();
    if (!connection_status_->has_state() ||
        connection_status_->state != now_connected)
      connection_status_->publish_state(now_connected);
  }
  if (connection_duration_ == nullptr)
    return;
  uint32_t now_ms = static_cast<uint32_t>(esp_timer_get_time() / 1000);
  uint32_t epoch = client_.connection_epoch();
  if (epoch != last_epoch_) {
    last_epoch_ = epoch;
    last_duration_publish_ms_ = 0;
  }
  if (now_ms - last_duration_publish_ms_ < 5000)
    return;
  last_duration_publish_ms_ = now_ms;
  uint32_t secs = client_.connected_duration_s();
  uint32_t d = secs / 86400;
  uint32_t h = (secs % 86400) / 3600;
  uint32_t m = (secs % 3600) / 60;
  char buf[24];
  snprintf(buf, sizeof(buf), "%02ud:%02uh:%02um",
           static_cast<unsigned>(d), static_cast<unsigned>(h),
           static_cast<unsigned>(m));
  if (last_duration_str_ != buf) {
    last_duration_str_ = buf;
    connection_duration_->publish_state(buf);
  }
}

void NpsComponent::dump_config() {
  ESP_LOGCONFIG(TAG, "NPS client:");
  ESP_LOGCONFIG(TAG, "  Server: %s:%u", config_.server,
                static_cast<unsigned>(config_.tcp_port));
  ESP_LOGCONFIG(TAG, "  Legacy version: %s", config_.legacy_version);
  ESP_LOGCONFIG(TAG, "  Runtime entities: server_text=%s tcp=%s vkey=%s "
                     "legacy_version_text=%s apply_button=%s rollback_switch=%s "
                     "connection_enabled_switch=%s",
                YESNO(server_text_ != nullptr), YESNO(tcp_port_text_ != nullptr),
                YESNO(vkey_text_ != nullptr),
                YESNO(legacy_version_text_ != nullptr),
                YESNO(config_apply_button_ != nullptr),
                YESNO(rollback_switch_ != nullptr),
                YESNO(connection_enabled_switch_ != nullptr));
}

void NpsComponent::on_shutdown() {
  stop_ = true;
  if (task_handle_ != nullptr)
    xTaskNotifyGive(task_handle_);
}

}  // namespace esphome::nps_origin
