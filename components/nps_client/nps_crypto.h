#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace esphome::nps {

// HMAC-SHA256(key=passwd, data = BE64(timestamp) + pieces...)，输出 32 字节。
void nps_compute_hmac(const char *passwd, int64_t timestamp,
                      const std::vector<std::vector<uint8_t>> &pieces,
                      uint8_t out[32]);

// BLAKE2b-256(vkey) 的小写 hex（64 字符）。
std::string nps_blake2b_hex(const char *vkey);

// SHA-256(vkey) 作为 AES-256 密钥。
void nps_vkey_aes_key(const char *vkey, uint8_t key[32]);

// AES-256-GCM 加密：输出 = 12 字节随机 nonce + 密文 + 16 字节 tag。
// 返回 false 表示失败（例如明文过长）。
bool nps_aes_gcm_encrypt(const uint8_t key[32], const uint8_t *plain,
                         size_t plain_len, std::vector<uint8_t> &out);

// 填充随机字节（esp_fill_random）。
void nps_random_bytes(uint8_t *buf, size_t len);

// 8 字节大端时间戳。
void nps_timestamp_be(int64_t ts, uint8_t out[8]);

// int32 LE 长度前缀 + 内容（内容非空时）。
void nps_append_len32(std::vector<uint8_t> &dst, const uint8_t *data, size_t len);

// 小写 hex 编码。
std::string nps_hex_lower(const uint8_t *data, size_t len);

}  // namespace esphome::nps
