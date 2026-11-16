#include <Arduino.h>
#include "soc/soc.h"
#include "soc/rtc_cntl_reg.h"

extern "C" void esp_brownout_init(void) {
    WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0);
    CLEAR_PERI_REG_MASK(RTC_CNTL_INT_ENA_REG, RTC_CNTL_BROWN_OUT_INT_ENA_M);
    WRITE_PERI_REG(RTC_CNTL_INT_CLR_REG, RTC_CNTL_BROWN_OUT_INT_CLR);
}
