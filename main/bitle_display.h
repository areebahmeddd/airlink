#ifndef BITLE_DISPLAY_H
#define BITLE_DISPLAY_H

#include "esp_err.h"

/* Probes for the SSD1306 and starts the refresh task if found. Always
 * returns ESP_OK when the display is absent (headless node). */
esp_err_t bitle_display_init(void);

#endif /* BITLE_DISPLAY_H */
