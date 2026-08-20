#pragma once

#include <cstddef>
#include <cstdint>
#include <memory_resource>

namespace esphome::nps {

// 大缓冲优先用 PSRAM（若启用且可用），否则回退内部 RAM。
uint8_t *nps_alloc(size_t size, bool use_psram);
void nps_free(uint8_t *buffer);

class NpsPsRamResource : public std::pmr::memory_resource {
 public:
  explicit NpsPsRamResource(bool use_psram = false) : use_psram_(use_psram) {}
  void set_use_psram(bool value) { use_psram_ = value; }

 protected:
  void *do_allocate(size_t bytes, size_t alignment) override;
  void do_deallocate(void *p, size_t bytes, size_t alignment) override;
  bool do_is_equal(const std::pmr::memory_resource &other) const noexcept override;

 private:
  bool use_psram_;
};

}  // namespace esphome::nps
