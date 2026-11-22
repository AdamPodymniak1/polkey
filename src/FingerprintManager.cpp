#include "FingerprintManager.h"
#include "DisplayManager.h"
#include "Globals.h"
#include "CryptoManager.h"
#include "StorageManager.h"
#include "CommsManager.h"
#include <ArduinoJson.h>

HardwareSerial mySerial(1);
Adafruit_Fingerprint finger = Adafruit_Fingerprint(&mySerial);

static bool fingerprintPowered = false;
static bool fingerprintReady = false;
static unsigned long fingerprintLastUseMs = 0;

void fingerprintKeepAlive() {
#if !AUTH_BUTTON_ONLY
    fingerprintLastUseMs = millis();
#endif
}

static void fingerprintRailOffLocked() {
#if !AUTH_BUTTON_ONLY
    if (!fingerprintPowered) return;

    mySerial.end();
    pinMode(FINGERPRINT_TX, OUTPUT);
    digitalWrite(FINGERPRINT_TX, LOW);
    pinMode(FINGERPRINT_RX, INPUT);

    digitalWrite(FINGERPRINT_POWER_PIN, LOW);
    fingerprintPowered = false;
    fingerprintReady = false;
#endif
}

bool fingerprintPowerOn() {
#if AUTH_BUTTON_ONLY
    return true;
#else
    fingerprintKeepAlive();
    if (fingerprintPowered) return fingerprintReady;

    pinMode(FINGERPRINT_POWER_PIN, OUTPUT);
    digitalWrite(FINGERPRINT_POWER_PIN, HIGH);
    fingerprintPowered = true;
    fingerprintReady = false;

    xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
    mySerial.begin(57600, SERIAL_8N1, FINGERPRINT_RX, FINGERPRINT_TX);
    finger.begin(57600);
    for (uint8_t attempt = 0; attempt < 3 && !fingerprintReady; attempt++) {
        if (attempt > 0) vTaskDelay(100 / portTICK_PERIOD_MS);
        fingerprintReady = finger.verifyPassword();
    }
    if (!fingerprintReady) {
        fingerprintRailOffLocked();
    }
    xSemaphoreGive(fingerprintMutex);

    fingerprintKeepAlive();

    if (!fingerprintReady) {
        Serial.println("[SYS:WARN] Fingerprint module did not answer after power-up");
    }
    return fingerprintReady;
#endif
}

void fingerprintPowerOff() {
#if !AUTH_BUTTON_ONLY
    xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
    fingerprintRailOffLocked();
    xSemaphoreGive(fingerprintMutex);
#endif
}

void fingerprintPowerIdleCheck() {
#if !AUTH_BUTTON_ONLY
    if (!fingerprintPowered) return;
    if (millis() - fingerprintLastUseMs < FINGERPRINT_IDLE_POWER_OFF_MS) return;

    if (xSemaphoreTake(fingerprintMutex, 0) != pdTRUE) return;
    if (fingerprintPowered &&
        millis() - fingerprintLastUseMs >= FINGERPRINT_IDLE_POWER_OFF_MS) {
        fingerprintRailOffLocked();
    }
    xSemaphoreGive(fingerprintMutex);
#endif
}

void setFingerprintLed(bool on) {
#if !AUTH_BUTTON_ONLY
    if (on) {
        fingerprintPowerOn();
    }
    if (!fingerprintPowered || !fingerprintReady) return;

    xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
    if (on) {
        finger.LEDcontrol(true);
        finger.LEDcontrol(FINGERPRINT_LED_ON, 0, FINGERPRINT_LED_BLUE, 0);
    } else {
        finger.LEDcontrol(false);
        finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, 0, 0);
    }
    xSemaphoreGive(fingerprintMutex);
    fingerprintKeepAlive();
#endif
}

void initFingerprintSensor() {
#if AUTH_BUTTON_ONLY
    pinMode(AUTH_BUTTON_PIN, INPUT_PULLUP);
    CommsManager::sendEvent("SYS", "BUTTON_READY");
#else
    if (fingerprintPowerOn()) {
        CommsManager::sendEvent("SYS", "FP_READY");
    } else {
        showDisplayMessage(1, "SENSOR ERROR!", "", 2000);
        CommsManager::sendError("SYS", "FP_SENSOR_ERROR");
    }

    fingerprintPowerOff();
#endif
}

bool enrollFingerprint(uint8_t id) {
#if AUTH_BUTTON_ONLY
    showDisplayMessage(1, "Press Button 1", "", 0);

    while(digitalRead(AUTH_BUTTON_PIN) == HIGH) { vTaskDelay(50 / portTICK_PERIOD_MS); }
    while(digitalRead(AUTH_BUTTON_PIN) == LOW) { vTaskDelay(50 / portTICK_PERIOD_MS); }

    showDisplayMessage(1, "Press Button 2", "", 0);

    while(digitalRead(AUTH_BUTTON_PIN) == HIGH) { vTaskDelay(50 / portTICK_PERIOD_MS); }
    while(digitalRead(AUTH_BUTTON_PIN) == LOW) { vTaskDelay(50 / portTICK_PERIOD_MS); }

    showDisplayMessage(1, "STORED OK", "", 2000);
    return true;
#else
    setFingerprintLed(true);
    xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
    finger.emptyDatabase();
    xSemaphoreGive(fingerprintMutex);

    int p = -1;

    showDisplayMessage(1, "Place finger", "", 0);

    while (p != FINGERPRINT_OK) {
        xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
        p = finger.getImage();
        xSemaphoreGive(fingerprintMutex);
        fingerprintKeepAlive();
        if (p != FINGERPRINT_OK) {
            vTaskDelay(50 / portTICK_PERIOD_MS);
        }
    }

    xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
    p = finger.image2Tz(1);
    xSemaphoreGive(fingerprintMutex);
    if (p != FINGERPRINT_OK) {
        setFingerprintLed(false);
        return false;
    }

    showDisplayMessage(1, "Remove finger", "", 0);
    vTaskDelay(1500 / portTICK_PERIOD_MS);

    p = 0;
    while (p != FINGERPRINT_NOFINGER) {
        xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
        p = finger.getImage();
        xSemaphoreGive(fingerprintMutex);
        fingerprintKeepAlive();
        vTaskDelay(50 / portTICK_PERIOD_MS);
    }

    showDisplayMessage(2, "Place SAME", "finger again", 0);

    p = -1;
    while (p != FINGERPRINT_OK) {
        xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
        p = finger.getImage();
        xSemaphoreGive(fingerprintMutex);
        fingerprintKeepAlive();
        if (p != FINGERPRINT_OK) {
            vTaskDelay(50 / portTICK_PERIOD_MS);
        }
    }

    xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
    p = finger.image2Tz(2);
    xSemaphoreGive(fingerprintMutex);
    if (p != FINGERPRINT_OK) {
        setFingerprintLed(false);
        return false;
    }

    xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
    p = finger.createModel();
    xSemaphoreGive(fingerprintMutex);
    if (p != FINGERPRINT_OK) {
        setFingerprintLed(false);
        showDisplayMessage(1, "MISMATCH!", "", 3000);
        return false;
    }

    xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
    p = finger.storeModel(id);
    xSemaphoreGive(fingerprintMutex);
    setFingerprintLed(false);
    if (p == FINGERPRINT_OK) {
        showDisplayMessage(1, "STORED OK", "", 2000);
        return true;
    } else {
        return false;
    }
#endif
}

void updateFingerprintAsync() {
    fingerprintPowerIdleCheck();
    if (currentCommandState != STATE_AWAITING_FINGERPRINT && currentCommandState != STATE_AWAITING_FINGERPRINT_UPDATE && currentCommandState != STATE_AWAITING_FINGERPRINT_SHOW) return;

#if AUTH_BUTTON_ONLY
    if (digitalRead(AUTH_BUTTON_PIN) == LOW) {
        while(digitalRead(AUTH_BUTTON_PIN) == LOW) { vTaskDelay(50 / portTICK_PERIOD_MS); }
        if (currentCommandState == STATE_AWAITING_FINGERPRINT_UPDATE) {
            deletePassword(pendingWebsite, pendingLogin);
            if (savePassword(pendingWebsite, pendingLogin, pendingPasswordToSave)) {
                CommsManager::sendEvent("PASS", "UPDATED");
                showDisplayMessage(1, "UPDATED!", "", 2000);
            } else {
                CommsManager::sendError("PASS", "UPDATE_FAILED");
            }
            secureWipe(pendingWebsite);
            secureWipe(pendingLogin);
            secureWipe(pendingPasswordToSave);
            currentCommandState = STATE_READY;
            return;
        }
        if (currentCommandState == STATE_AWAITING_FINGERPRINT_SHOW) {
            JsonDocument data;
            data["site"] = pendingWebsite;
            data["login"] = pendingLogin;
            data["password"] = pendingPasswordToTransmit;
            CommsManager::sendEvent("PASS", "DISPLAYED", &data);

            secureWipe(pendingPasswordToTransmit);
            secureWipe(pendingWebsite);
            secureWipe(pendingLogin);
            currentCommandState = STATE_READY;

            showDisplayMessage(1, "DISPLAYED!", "", 2000);
            return;
        }
        String challengeNonce = generateRandomPassword(16);
        String securePayload = challengeNonce + "1";
        String computedResponse = hashSHA256(securePayload);

        JsonDocument data;
        data["password"] = pendingPasswordToTransmit;
        CommsManager::sendEvent("PASS", "TRANSMITTED", &data);

        secureWipe(pendingPasswordToTransmit);
        currentCommandState = STATE_READY;

        showDisplayMessage(1, "TRANSMITTED!", "", 0);
    }
#else
    fingerprintPowerOn();
    xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
    uint8_t imageResult = finger.getImage();
    xSemaphoreGive(fingerprintMutex);

    for (uint8_t retry = 0; retry < 3 && imageResult != FINGERPRINT_OK && imageResult != FINGERPRINT_NOFINGER; retry++) {
        vTaskDelay(50 / portTICK_PERIOD_MS);
        xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
        imageResult = finger.getImage();
        xSemaphoreGive(fingerprintMutex);
    }

    if (imageResult == FINGERPRINT_OK) {
        xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
        uint8_t tzResult = finger.image2Tz();
        xSemaphoreGive(fingerprintMutex);

        if (tzResult == FINGERPRINT_OK) {
            String challengeNonce = generateRandomPassword(16);

            xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
            uint8_t searchResult = finger.fingerSearch();
            uint8_t matchedID = finger.fingerID;
            uint16_t matchConfidence = finger.confidence;
            xSemaphoreGive(fingerprintMutex);

            if (searchResult == FINGERPRINT_OK) {
                if (matchConfidence == lastConfidenceScore && matchConfidence > 0) {
                    showDisplayMessage(1, "REPLAY DETECTED", "", 2000);
                    CommsManager::sendError("AUTH", "REPLAY_DETECTED");
                    currentCommandState = STATE_READY;
                    setFingerprintLed(false);
                    return;
                }
                lastConfidenceScore = matchConfidence;

                if (matchConfidence > 50) {
                    if (currentCommandState == STATE_AWAITING_FINGERPRINT_UPDATE) {
                        deletePassword(pendingWebsite, pendingLogin);
                        if (savePassword(pendingWebsite, pendingLogin, pendingPasswordToSave)) {
                            CommsManager::sendEvent("PASS", "UPDATED");
                            showDisplayMessage(1, "UPDATED!", "", 2000);
                        } else {
                            CommsManager::sendError("PASS", "UPDATE_FAILED");
                        }
                        secureWipe(pendingWebsite);
                        secureWipe(pendingLogin);
                        secureWipe(pendingPasswordToSave);
                        currentCommandState = STATE_READY;
                        setFingerprintLed(false);
                        return;
                    }
                    if (currentCommandState == STATE_AWAITING_FINGERPRINT_SHOW) {
                        JsonDocument data;
                        data["site"] = pendingWebsite;
                        data["login"] = pendingLogin;
                        data["password"] = pendingPasswordToTransmit;
                        CommsManager::sendEvent("PASS", "DISPLAYED", &data);

                        secureWipe(pendingPasswordToTransmit);
                        secureWipe(pendingWebsite);
                        secureWipe(pendingLogin);
                        currentCommandState = STATE_READY;
                        setFingerprintLed(false);

                        showDisplayMessage(1, "DISPLAYED!", "", 0);

                        unsigned long startWait = millis();
                        while (millis() - startWait < 1200) { vTaskDelay(10 / portTICK_PERIOD_MS); }

                        showDisplayMessage(1, "Logged In", "", 0);
                        return;
                    }
                    
                    String securePayload = challengeNonce + String(matchedID);
                    String computedResponse = hashSHA256(securePayload); 

                    JsonDocument data;
                    data["password"] = pendingPasswordToTransmit;
                    CommsManager::sendEvent("PASS", "TRANSMITTED", &data);

                    secureWipe(pendingPasswordToTransmit);
                    currentCommandState = STATE_READY;
                    setFingerprintLed(false);

                    showDisplayMessage(1, "TRANSMITTED!", "", 0);

                    unsigned long startWait = millis();
                    while (millis() - startWait < 1200) { vTaskDelay(10 / portTICK_PERIOD_MS); }

                    showDisplayMessage(1, "Logged In", "", 0);
                } else {
                    showDisplayMessage(1, "Try again", "", 1000);
                    CommsManager::sendError("AUTH", "LOW_CONFIDENCE");
                }
            } else {
                showDisplayMessage(1, "Unknown Finger", "", 2000);
                CommsManager::sendError("AUTH", "UNKNOWN_FINGER");
            }
        } else {
            vTaskDelay(500 / portTICK_PERIOD_MS);
        }
    } 
    else if (imageResult != FINGERPRINT_NOFINGER) {
        vTaskDelay(500 / portTICK_PERIOD_MS);
    }
#endif
}

void deleteAllFingerprints() {
#if !AUTH_BUTTON_ONLY
    fingerprintPowerOn();
    xSemaphoreTake(fingerprintMutex, portMAX_DELAY);
    finger.emptyDatabase();
    xSemaphoreGive(fingerprintMutex);
    fingerprintKeepAlive();
#endif
}