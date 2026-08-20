#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 仅实现顺序模式的 BLAKE2b，输出 32 字节（BLAKE2b-256）。
// 参考公共领域实现（RFC 7693 附录），压缩到最小可读形式。
int nps_blake2b_256(const uint8_t *input, size_t inlen, uint8_t out[32]);

#ifdef __cplusplus
}
#endif
