#include "nps_crypto.h"

#include <cstring>

#include "esp_random.h"
#include "mbedtls/md.h"

namespace esphome::nps_origin {

std::string nps_md5_hex(const char *text) {
  uint8_t digest[16];
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
  mbedtls_md(info, reinterpret_cast<const uint8_t *>(text), strlen(text), digest);
  return nps_hex_lower(digest, sizeof(digest));
}

void nps_append_len32(std::vector<uint8_t> &dst, const uint8_t *data,
                      size_t len) {
  uint32_t l = static_cast<uint32_t>(len);
  dst.push_back(static_cast<uint8_t>(l & 0xFF));
  dst.push_back(static_cast<uint8_t>((l >> 8) & 0xFF));
  dst.push_back(static_cast<uint8_t>((l >> 16) & 0xFF));
  dst.push_back(static_cast<uint8_t>((l >> 24) & 0xFF));
  if (len > 0)
    dst.insert(dst.end(), data, data + len);
}

void nps_random_bytes(uint8_t *buf, size_t len) {
  if (buf == nullptr || len == 0)
    return;
  esp_fill_random(buf, len);
}

std::string nps_hex_lower(const uint8_t *data, size_t len) {
  static const char hex[] = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; i++) {
    out.push_back(hex[data[i] >> 4]);
    out.push_back(hex[data[i] & 15]);
  }
  return out;
}

}  // namespace esphome::nps_origin
