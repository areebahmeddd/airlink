#include "lora_airtime.h"

#include <math.h>

bool lora_airtime_params_valid(const lora_airtime_params_t *params)
{
    if (!params || params->spreading_factor < 5 || params->spreading_factor > 12 ||
        params->coding_rate < 5 || params->coding_rate > 8 ||
        params->preamble_symbols < 4) {
        return false;
    }
    return params->bandwidth_hz == 125000 ||
           params->bandwidth_hz == 250000 ||
           params->bandwidth_hz == 500000;
}

uint32_t lora_airtime_ms(const lora_airtime_params_t *params, uint16_t payload_len)
{
    if (!lora_airtime_params_valid(params) || payload_len == 0 || payload_len > 255) {
        return 0;
    }

    const double sf = params->spreading_factor;
    const double symbol_s = (double)(1u << params->spreading_factor) /
                            (double)params->bandwidth_hz;
    const bool low_data_rate_optimize =
        (params->spreading_factor >= 11 && params->bandwidth_hz == 125000) ||
        (params->spreading_factor >= 12 && params->bandwidth_hz == 250000);
    const double numerator =
        8.0 * payload_len -
        4.0 * sf +
        28.0 +
        (params->crc_enabled ? 16.0 : 0.0) -
        (params->explicit_header ? 0.0 : 20.0);
    const double denominator =
        4.0 * (sf - (low_data_rate_optimize ? 2.0 : 0.0));
    double payload_symbols =
        ceil(numerator / denominator) * (params->coding_rate);
    if (payload_symbols < 0.0) {
        payload_symbols = 0.0;
    }
    payload_symbols += 8.0;

    const double preamble_s = (params->preamble_symbols + 4.25) * symbol_s;
    const double total_ms = (preamble_s + payload_symbols * symbol_s) * 1000.0;
    return (uint32_t)(total_ms + 0.5);
}
