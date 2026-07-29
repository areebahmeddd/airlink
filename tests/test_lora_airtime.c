#include "lora_airtime.h"

#include <assert.h>
#include <stdint.h>

int main(void)
{
    lora_airtime_params_t params = {
        .spreading_factor = 10,
        .bandwidth_hz = 125000,
        .coding_rate = 5,
        .preamble_symbols = 8,
        .explicit_header = true,
        .crc_enabled = true,
    };
    assert(lora_airtime_params_valid(&params));
    assert(lora_airtime_ms(&params, 136) == 1313);

    const uint32_t expected_ms[] = {51, 93, 165, 330, 659, 1319};
    for (uint8_t sf = 7; sf <= 12; ++sf) {
        params.spreading_factor = sf;
        assert(lora_airtime_ms(&params, 16) == expected_ms[sf - 7]);
    }

    params.spreading_factor = 13;
    assert(!lora_airtime_params_valid(&params));
    assert(lora_airtime_ms(&params, 136) == 0);
    return 0;
}
