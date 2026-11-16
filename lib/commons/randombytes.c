#include "randombytes.h"
#include <esp_random.h> /* esp_fill_random(); not exported by esp_system.h on ESP-IDF 5.x */
#include <stdint.h>
#include <stddef.h>

int PQCLEAN_randombytes(uint8_t *buf, size_t n) {
    esp_fill_random(buf, n);
    return 0;
}