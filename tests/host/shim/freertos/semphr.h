#pragma once
#include "FreeRTOS.h"
int host_sem_take(SemaphoreHandle_t h);
int host_sem_give(SemaphoreHandle_t h);
#define xSemaphoreTake(h, t) host_sem_take(h)
#define xSemaphoreGive(h) host_sem_give(h)
