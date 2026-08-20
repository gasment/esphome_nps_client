#include "nps_mem.h"

#include <cstdlib>

#include "esp_heap_caps.h"

namespace esphome::nps_origin {

uint8_t *nps_alloc(size_t size, bool use_psram) {
  if (size == 0)
    return nullptr;
  void *ptr = nullptr;
  if (use_psram) {
    ptr = heap_caps_malloc(size, MALLOC_CAP_SPIRAM);
    if (ptr == nullptr)
      ptr = heap_caps_malloc(size, MALLOC_CAP_8BIT);
  } else {
    ptr = heap_caps_malloc(size, MALLOC_CAP_8BIT);
  }
  return static_cast<uint8_t *>(ptr);
}

void nps_free(uint8_t *buffer) {
  if (buffer != nullptr)
    heap_caps_free(buffer);
}

void *NpsPsRamResource::do_allocate(size_t bytes, size_t alignment) {
  if (alignment <= alignof(std::max_align_t))
    return nps_alloc(bytes, use_psram_);
  // 极少数对齐要求超过默认，退回标准分配。
  void *ptr = nullptr;
  if (posix_memalign(&ptr, alignment, bytes) != 0)
    return nullptr;
  return ptr;
}

void NpsPsRamResource::do_deallocate(void *p, size_t bytes, size_t alignment) {
  if (p == nullptr)
    return;
  if (alignment <= alignof(std::max_align_t)) {
    nps_free(static_cast<uint8_t *>(p));
  } else {
    std::free(p);
  }
}

bool NpsPsRamResource::do_is_equal(
    const std::pmr::memory_resource &other) const noexcept {
  return this == &other;
}

}  // namespace esphome::nps_origin
