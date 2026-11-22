#pragma once
#include <stdint.h>
#define portMAX_DELAY 0xFFFFFFFFu
#define portTICK_PERIOD_MS 1
typedef void *SemaphoreHandle_t;
typedef void *QueueHandle_t;
typedef void *TaskHandle_t;
typedef uint32_t TickType_t;
