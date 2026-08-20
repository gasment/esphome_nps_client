#pragma once

#include <atomic>
#include <cstdio>
#include <string>

#include "esphome/components/binary_sensor/binary_sensor.h"
#include "esphome/components/button/button.h"
#include "esphome/components/select/select.h"
#include "esphome/components/switch/switch.h"
#include "esphome/components/text/text.h"
#include "esphome/components/text_sensor/text_sensor.h"
#include "esphome/core/component.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "nps_client.h"
#include "nps_config.h"

namespace esphome::nps {

class NpsComponent;

// 运行时可编辑实体：修改即写入 slotB 预配置
class NpsConfigText final : public text::Text {
 public:
  void control(const std::string &value) override { this->publish_state(value); }
};

class NpsConfigSelect final : public select::Select {
 public:
  void control(const std::string &value) override { this->publish_state(value); }
  void control(size_t index) override { this->publish_state(index); }
};

class NpsConfigApplyButton final : public button::Button {
 public:
  explicit NpsConfigApplyButton(NpsComponent *parent) : parent_(parent) {}
  void press_action() override;

 protected:
  NpsComponent *parent_;
};

class NpsConfigSwitch final : public switch_::Switch, public Component {
 public:
  explicit NpsConfigSwitch(NpsComponent *parent) : parent_(parent) {}
  void setup() override;
  float get_setup_priority() const override {
    return setup_priority::HARDWARE - 2.0f;
  }
  void write_state(bool state) override;

 protected:
  NpsComponent *parent_;
};

class NpsComponent : public Component {
 public:
  void setup() override;
  void loop() override;
  void dump_config() override;
  float get_setup_priority() const override { return setup_priority::AFTER_WIFI; }
  void on_shutdown() override;

  // ---- 编译期配置（slotA 初始值 / 静态兜底）----
  void set_server(const std::string &value) {
    snprintf(config_.server, sizeof(config_.server), "%s", value.c_str());
  }
  void set_mode(const std::string &value) {
    snprintf(config_.mode, sizeof(config_.mode), "%s", value.c_str());
  }
  void set_tcp_port(uint16_t value) { config_.tcp_port = value; }
  void set_tls_port(uint16_t value) { config_.tls_port = value; }
  void set_vkey(const std::string &value) {
    snprintf(config_.vkey, sizeof(config_.vkey), "%s", value.c_str());
  }
  void set_local_ip(const std::string &value) {
    snprintf(config_.local_ip, sizeof(config_.local_ip), "%s", value.c_str());
  }
  void set_connect_timeout_s(uint16_t value) { config_.connect_timeout_s = value; }
  void set_proto_version(uint8_t value) { config_.proto_version = value; }
  void set_reconnect_delay_s(uint16_t value) { config_.reconnect_delay_s = value; }
  void set_disconnect_timeout_s(uint16_t value) {
    config_.disconnect_timeout_s = value;
  }
  void set_use_psram(bool value) { config_.use_psram = value; }
  void set_task_stack(uint32_t value) { task_stack_ = value; }
  void set_connection_status(binary_sensor::BinarySensor *s) {
    connection_status_ = s;
  }
  void set_connection_duration(text_sensor::TextSensor *s) {
    connection_duration_ = s;
  }

  // ---- 运行时实体注入 ----
  void set_server_text(text::Text *t) { server_text_ = t; }
  void set_tcp_port_text(text::Text *t) { tcp_port_text_ = t; }
  void set_tls_port_text(text::Text *t) { tls_port_text_ = t; }
  void set_vkey_text(text::Text *t) { vkey_text_ = t; }
  void set_mode_select(select::Select *s) { mode_select_ = s; }
  void set_config_apply_button(button::Button *b) { config_apply_button_ = b; }
  void set_config_rollback_switch(switch_::Switch *s) {
    rollback_switch_ = s;
  }
  void set_connection_enabled_switch(switch_::Switch *s) {
    connection_enabled_switch_ = s;
  }
  // 实体的 initial_value（首次启动时补齐 slotA）
  void set_initial_server(const std::string &v) { initial_server_ = v; }
  void set_initial_tcp_port(const std::string &v) { initial_tcp_port_ = v; }
  void set_initial_tls_port(const std::string &v) { initial_tls_port_ = v; }
  void set_initial_vkey(const std::string &v) { initial_vkey_ = v; }
  void set_initial_mode(const std::string &v) { initial_mode_ = v; }

  // 应用 slotB 预配置：成功固化 slotA，失败回滚（按钮触发）
  void config_apply();

 private:
  static void task_entry_(void *arg);
  void task_();
  NpsConfig config_snapshot_();
  bool config_valid_(const NpsConfig &c) const;
  void start_task_();
  void load_nvs_(NpsConfig &c);
  void init_pending_();
  void init_entities_();
  void persist_nvs_(const NpsConfig &c);
  void persist_slot_a_();
  void on_server_changed(const std::string &value);
  void on_tcp_port_changed(const std::string &value);
  void on_tls_port_changed(const std::string &value);
  void on_vkey_changed(const std::string &value);
  void on_mode_changed(const std::string &value);
  void on_rollback_switch_changed(bool value);
  void on_connection_enabled_changed(bool value);
  static bool parse_port_(const std::string &value, uint16_t &out);
  void rollback_();
  void stop_connection_();

  NpsConfig config_{};         // slotA：当前生效（已应用）配置
  NpsConfig pending_{};        // slotB：预配置（实体编辑目标）
  NpsConfig slot_a_backup_{};  // 应用失败回滚用
  SemaphoreHandle_t mutex_{nullptr};
  NpsClient client_;
  std::atomic<bool> stop_{false};
  std::atomic<bool> reload_{false};
  TaskHandle_t task_handle_{nullptr};
  text::Text *server_text_{nullptr};
  text::Text *tcp_port_text_{nullptr};
  text::Text *tls_port_text_{nullptr};
  text::Text *vkey_text_{nullptr};
  select::Select *mode_select_{nullptr};
  button::Button *config_apply_button_{nullptr};
  switch_::Switch *rollback_switch_{nullptr};
  switch_::Switch *connection_enabled_switch_{nullptr};
  std::string initial_server_;
  std::string initial_tcp_port_;
  std::string initial_tls_port_;
  std::string initial_vkey_;
  std::string initial_mode_;
  bool applying_{false};
  bool syncing_entities_{false};
  bool rollback_enabled_{true};
  bool connection_enabled_{true};
  uint32_t apply_deadline_ms_{0};
  uint32_t apply_epoch_{0};
  binary_sensor::BinarySensor *connection_status_{nullptr};
  text_sensor::TextSensor *connection_duration_{nullptr};
  uint32_t last_duration_publish_ms_{0};
  uint32_t last_epoch_{0};
  std::string last_duration_str_;
  uint32_t task_stack_{14336};
};

}  // namespace esphome::nps
