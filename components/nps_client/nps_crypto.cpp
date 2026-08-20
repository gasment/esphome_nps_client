#include "nps_crypto.h"

#include <cstring>

#include "blake2b.h"
#include "esp_random.h"
#include "mbedtls/cipher.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"

namespace esphome::nps {

void nps_compute_hmac(const char *passwd, int64_t timestamp,
                      const std::vector<std::vector<uint8_t>> &pieces,
                      uint8_t out[32]) {
  uint8_t ts[8];
  nps_timestamp_be(timestamp, ts);
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, info, 1);
  mbedtls_md_hmac_starts(&ctx, reinterpret_cast<const uint8_t *>(passwd),
                         strlen(passwd));
  mbedtls_md_hmac_update(&ctx, ts, sizeof(ts));
  for (const auto &piece : pieces)
    mbedtls_md_hmac_update(&ctx, piece.data(), piece.size());
  mbedtls_md_hmac_finish(&ctx, out);
  mbedtls_md_free(&ctx);
}

std::string nps_blake2b_hex(const char *vkey) {
  uint8_t digest[32];
  nps_blake2b_256(reinterpret_cast<const uint8_t *>(vkey), strlen(vkey), digest);
  return nps_hex_lower(digest, sizeof(digest));
}

void nps_vkey_aes_key(const char *vkey, uint8_t key[32]) {
  mbedtls_sha256(reinterpret_cast<const uint8_t *>(vkey), strlen(vkey), key, 0);
}

bool nps_aes_gcm_encrypt(const uint8_t key[32], const uint8_t *plain,
                         size_t plain_len, std::vector<uint8_t> &out) {
  if (plain_len > 0x7FFFFF00)
    return false;  // 防止 gcm 内部 size 溢出
  constexpr size_t NONCE_LEN = 12;
  constexpr size_t TAG_LEN = 16;
  out.resize(NONCE_LEN + plain_len + TAG_LEN);
  uint8_t *nonce = out.data();
  uint8_t *ct = out.data() + NONCE_LEN;
  uint8_t *tag = ct + plain_len;
  nps_random_bytes(nonce, NONCE_LEN);

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (rc != 0) {
    mbedtls_gcm_free(&gcm);
    return false;
  }
  rc = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plain_len, nonce,
                                 NONCE_LEN, nullptr, 0, plain, ct, TAG_LEN,
                                 tag);
  mbedtls_gcm_free(&gcm);
  return rc == 0;
}

void nps_random_bytes(uint8_t *buf, size_t len) {
  if (buf == nullptr || len == 0)
    return;
  esp_fill_random(buf, len);
}

void nps_timestamp_be(int64_t ts, uint8_t out[8]) {
  uint64_t v = static_cast<uint64_t>(ts);
  for (int i = 7; i >= 0; i--) {
    out[i] = static_cast<uint8_t>(v & 0xFF);
    v >>= 8;
  }
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

}  // namespace esphome::nps
