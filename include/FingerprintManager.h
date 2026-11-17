#ifndef FINGERPRINT_MANAGER_H
#define FINGERPRINT_MANAGER_H

#include <Adafruit_Fingerprint.h>

// UART pin map for the fingerprint module.
#define FINGERPRINT_RX 16
#define FINGERPRINT_TX 17
#define FINGERPRINT_POWER_PIN 4
#define FINGERPRINT_IDLE_POWER_OFF_MS 15000

extern HardwareSerial mySerial;
extern Adafruit_Fingerprint finger;

void initFingerprintSensor();
bool enrollFingerprint(uint8_t id);
void updateFingerprintAsync();
void deleteAllFingerprints();
void setFingerprintLed(bool on);

bool fingerprintPowerOn();
void fingerprintPowerOff();
void fingerprintPowerIdleCheck();
void fingerprintKeepAlive();

#endif