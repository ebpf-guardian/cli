#include <stdint.h>

struct bpf_map_def {
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t flags;
};

__attribute__((section("maps")))
struct bpf_map_def test_map = {
    .type = 1,  // BPF_MAP_TYPE_HASH
    .key_size = 4,
    .value_size = 4,
    .max_entries = 10000,
    .flags = 0,
};

__attribute__((section("prog")))
int test_prog(void *ctx) {
    return 0;
}