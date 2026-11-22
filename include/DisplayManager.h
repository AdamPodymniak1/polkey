#ifndef DISPLAY_MANAGER_H
#define DISPLAY_MANAGER_H

#include <Arduino.h>
#include "FeatureConfig.h"

#if FEATURE_OLED
#include <U8g2lib.h>
#include <SPI.h>

// Shared OLED instance guarded by displayMutex.
extern U8G2_SSD1306_128X32_UNIVISION_F_4W_SW_SPI u8g2;
#endif


void showDisplayMessage(int lines, String text1, String text2 = "", unsigned long timeoutMs = 0, bool requireStay = false);
void clearDisplay();

#endif 
