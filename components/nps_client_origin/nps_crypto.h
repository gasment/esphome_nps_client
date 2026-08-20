#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace esphome::nps_origin {

// MD5 小写 hex（32 字符），旧版 ehang-io/nps 认证使用。
std::string nps_md5_hex(const char *text);

// int32 LE 长度前缀 + 内容。
void nps_append_len32(std::vector<uint8_t> &dst, const uint8_t *data,
                      size_t len);

// 填充随机字节（esp_fill_random），用于 mux ping 填充。
void nps_random_bytes(uint8_t *buf, size_t len);

// 小写 hex 编码。
std::string nps_hex_lower(const uint8_t *data, size_t len);

}  // namespace esphome::nps_origin
