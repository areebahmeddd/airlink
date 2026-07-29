#include "lora_airtime.h"

#include <assert.h>
#include <stddef.h>
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

    params.preamble_symbols = 16;
    const uint16_t frame_sizes[] = {16, 136, 255};
    for (uint8_t sf = 7; sf <= 12; ++sf) {
        params.spreading_factor = sf;
        for (size_t i = 0; i < sizeof(frame_sizes) / sizeof(frame_sizes[0]); ++i) {
            uint32_t airtime = lora_airtime_ms(&params, frame_sizes[i]);
            uint32_t timeout =
                lora_tx_timeout_ms(&params, frame_sizes[i], 500, 25);
            uint32_t percentage_margin = (airtime * 25u + 99u) / 100u;
            uint32_t expected_margin =
                percentage_margin > 500 ? percentage_margin : 500;
            assert(airtime > 0);
            assert(timeout == airtime + expected_margin);
            assert(lora_sx126x_timeout_units(timeout) <
                   LORA_SX126X_TIMEOUT_UNITS_MAX);
        }
    }
    assert(lora_sx126x_timeout_units(UINT32_MAX) ==
           LORA_SX126X_TIMEOUT_UNITS_MAX);
    return 0;
}
