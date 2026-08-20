#pragma once

#include <cstdint>
#include <string>

namespace esphome::nps_origin {

// 极简 JSON 取值器，仅用于解析服务端下发的 Link 对象。
// path 形如 "Host" 或 "Option.Timeout"。
std::string nps_json_string(const std::string &json, const char *path);
bool nps_json_bool(const std::string &json, const char *path, bool fallback);
int64_t nps_json_int64(const std::string &json, const char *path,
                       int64_t fallback);

}  // namespace esphome::nps_origin
