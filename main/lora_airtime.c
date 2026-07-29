#include "lora_airtime.h"

#include <limits.h>
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

uint32_t lora_tx_timeout_ms(const lora_airtime_params_t *params,
                            uint16_t payload_len,
                            uint32_t minimum_margin_ms,
                            uint8_t margin_percent)
{
    uint32_t airtime = lora_airtime_ms(params, payload_len);
    if (airtime == 0) {
        return 0;
    }
    uint64_t percent_margin = ((uint64_t)airtime * margin_percent + 99u) / 100u;
    uint64_t margin = percent_margin > minimum_margin_ms
                          ? percent_margin
                          : minimum_margin_ms;
    uint64_t timeout = (uint64_t)airtime + margin;
    return timeout > UINT32_MAX ? UINT32_MAX : (uint32_t)timeout;
}

uint32_t lora_sx126x_timeout_units(uint32_t timeout_ms)
{
    uint64_t units = (uint64_t)timeout_ms * 64u;
    return units > LORA_SX126X_TIMEOUT_UNITS_MAX
               ? LORA_SX126X_TIMEOUT_UNITS_MAX
               : (uint32_t)units;
}
