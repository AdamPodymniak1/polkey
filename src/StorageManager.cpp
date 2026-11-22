#include "StorageManager.h"
#include "CryptoManager.h"
#include "CommsManager.h"
#include "FingerprintManager.h"
#include "SPIFFS.h"
#include <ArduinoJson.h>
#include "Globals.h"
#include <vector>
#include "mbedtls/pkcs5.h"
#include "mbedtls/aes.h"
#include <nvs_flash.h>
#include <nvs.h>

static byte storageKey[32] = {0};
static bool isStorageKeyLoaded = false;

static String readSpiffsString(File &file) {
    uint16_t len;
    if (file.read((uint8_t*)&len, 2) != 2) return "";
    if (len == 0) return "";
    if ((size_t)len > (size_t)file.available()) {
        file.seek(0, SeekEnd);
        return "";
    }
    char* buf = (char*)calloc((size_t)len + 1, 1);
    if (!buf) return "";
    if (file.read((uint8_t*)buf, len) != (size_t)len) {
        free(buf);
        file.seek(0, SeekEnd);
        return "";
    }
    String res(buf);
    free(buf);
    return res;
}

static bool readPayloadString(File &file, uint16_t len, String &out) {
    out = "";
    if (len == 0) return true;
    if ((size_t)len > (size_t)file.available()) {
        file.seek(0, SeekEnd);
        return false;
    }
    char* buf = (char*)calloc((size_t)len + 1, 1);
    if (!buf) return false;
    if (file.read((uint8_t*)buf, len) != (size_t)len) {
        free(buf);
        file.seek(0, SeekEnd);
        return false;
    }
    out = String(buf);
    free(buf);
    return true;
}

struct PasskeyFrame {
    uint8_t status = 0;
    int32_t algId = 0;
    String cid;
    String rp;
    uint16_t payLen = 0;
};

static bool readFrameString(File &file, String &out) {
    out = "";
    uint16_t len;
    if (file.read((uint8_t*)&len, 2) != 2) return false;
    if ((size_t)len > (size_t)file.available()) return false;
    if (len == 0) return true;
    char* buf = (char*)calloc((size_t)len + 1, 1);
    if (!buf) return false;
    bool ok = file.read((uint8_t*)buf, len) == (size_t)len;
    if (ok) out = String(buf);
    free(buf);
    return ok;
}

static bool readPasskeyFrame(File &file, PasskeyFrame &f) {
    if (file.read(&f.status, 1) != 1) return false;
    if (file.read((uint8_t*)&f.algId, 4) != 4) return false;
    if (!readFrameString(file, f.cid)) return false;
    if (!readFrameString(file, f.rp)) return false;
    if (file.read((uint8_t*)&f.payLen, 2) != 2) return false;
    return (size_t)f.payLen <= (size_t)file.available();
}

static void appendPasskeyFrame(std::vector<uint8_t> &out, uint8_t status, int32_t algId, const String &cid, const String &rp, const String &payload) {
    out.push_back(status);
    const uint8_t *alg = (const uint8_t *)&algId;
    out.insert(out.end(), alg, alg + 4);
    const String *fields[3] = {&cid, &rp, &payload};
    for (const String *f : fields) {
        uint16_t fl = (uint16_t)f->length();
        const uint8_t *lb = (const uint8_t *)&fl;
        out.insert(out.end(), lb, lb + 2);
        out.insert(out.end(), (const uint8_t *)f->c_str(), (const uint8_t *)f->c_str() + fl);
    }
}

static bool replacePasskeyFile(const std::vector<uint8_t> &content) {
    File tmp = SPIFFS.open("/passkeys.tmp", "w");
    if (!tmp) return false;
    size_t written = content.empty() ? 0 : tmp.write(content.data(), content.size());
    tmp.close();
    if (written != content.size()) {
        SPIFFS.remove("/passkeys.tmp");
        return false;
    }
    SPIFFS.remove("/passkeys.bin");
    SPIFFS.rename("/passkeys.tmp", "/passkeys.bin");
    return true;
}

static int hexNibble(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static bool hexDecodeStrict(const String &hex, uint8_t *out, size_t expectedBytes) {
    if (hex.length() != expectedBytes * 2) return false;
    for (size_t i = 0; i < expectedBytes; i++) {
        int hi = hexNibble(hex[2 * i]);
        int lo = hexNibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static void secureZero(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

static bool constantTimeEqual(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

struct PasskeyPayload {
    String userIdHex;
    String userName;
    String privateKeyHex;
    int credProtect = 1;
    String largeBlobKeyHex;
    String credBlobHex;
};

static String buildPasskeyPayload(const String &userIdHex, const String &userName, const String &privateKeyHex,
                                  int credProtect, const String &largeBlobKeyHex, const String &credBlobHex) {
    String nameHex = toHex((const byte *)userName.c_str(), userName.length());
    return String("V2\n") + userIdHex + "\n" + nameHex + "\n" + privateKeyHex + "\n" + String(credProtect) + "\n" + largeBlobKeyHex + "\n" + credBlobHex;
}

static bool parsePasskeyPayload(const String &payload, PasskeyPayload &out) {
    out = PasskeyPayload();
    int n1 = payload.indexOf('\n');
    if (n1 == -1) return false;

    if (payload.substring(0, n1) == "V2") {
        String fields[6];
        int start = n1 + 1;
        for (int i = 0; i < 6; i++) {
            int nl = (i < 5) ? payload.indexOf('\n', start) : -1;
            if (i < 5 && nl == -1) return false;
            fields[i] = (i < 5) ? payload.substring(start, nl) : payload.substring(start);
            start = nl + 1;
        }
        size_t nameBytes = fields[1].length() / 2;
        if (fields[1].length() % 2 != 0 || nameBytes > 1024) return false;
        String name;
        if (nameBytes > 0) {
            uint8_t *tmp = (uint8_t *)calloc(nameBytes + 1, 1);
            if (!tmp) return false;
            bool ok = hexDecodeStrict(fields[1], tmp, nameBytes);
            if (ok) name = String((const char *)tmp);
            free(tmp);
            if (!ok) return false;
        }
        out.userIdHex = fields[0];
        out.userName = name;
        out.privateKeyHex = fields[2];
        out.credProtect = fields[3].length() > 0 ? fields[3].toInt() : 1;
        out.largeBlobKeyHex = fields[4];
        out.credBlobHex = fields[5];
        return true;
    }

    int firstNewline = n1;
    int secondNewline = payload.indexOf('\n', firstNewline + 1);
    if (secondNewline == -1) return false;

    out.userIdHex = payload.substring(0, firstNewline);
    out.userName = payload.substring(firstNewline + 1, secondNewline);

    int thirdNewline = payload.indexOf('\n', secondNewline + 1);
    int fourthNewline = (thirdNewline == -1) ? -1 : payload.indexOf('\n', thirdNewline + 1);
    int fifthNewline = (fourthNewline == -1) ? -1 : payload.indexOf('\n', fourthNewline + 1);

    if (thirdNewline == -1) {
        out.privateKeyHex = payload.substring(secondNewline + 1);
    } else {
        out.privateKeyHex = payload.substring(secondNewline + 1, thirdNewline);
        if (fourthNewline == -1) {
            String cp = payload.substring(thirdNewline + 1);
            if (cp.length() > 0) out.credProtect = cp.toInt();
        } else {
            String cp = payload.substring(thirdNewline + 1, fourthNewline);
            if (cp.length() > 0) out.credProtect = cp.toInt();
            if (fifthNewline == -1) {
                out.largeBlobKeyHex = payload.substring(fourthNewline + 1);
            } else {
                out.largeBlobKeyHex = payload.substring(fourthNewline + 1, fifthNewline);
                out.credBlobHex = payload.substring(fifthNewline + 1);
            }
        }
    }
    return true;
}

static bool rpFieldMatchesRpId(const String &storedRpField, const String &plainRpId) {
    if (storedRpField == plainRpId) return true;
    return storedRpField == hashSHA256(plainRpId);
}

void deriveStorageKey(const String &pin) {
    const unsigned char salt[] = "VAULT_STORAGE_SALT";

    mbedtls_pkcs5_pbkdf2_hmac_ext(
        MBEDTLS_MD_SHA256,
        (const unsigned char *)pin.c_str(),
        pin.length(),
        salt,
        sizeof(salt) - 1,
        10000,
        32,
        storageKey
    );

    isStorageKeyLoaded = true;
}

void clearStorageKey() {
    memset(storageKey, 0, sizeof(storageKey));
    isStorageKeyLoaded = false;
}

bool initStorage() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    bool res = SPIFFS.begin(true);
    xSemaphoreGive(storageMutex);
    return res;
}

String hashPin(const String &pin) {
    byte shaResult[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, (const unsigned char *)pin.c_str(), pin.length());
    mbedtls_md_finish(&ctx, shaResult);
    mbedtls_md_free(&ctx);
    return toHex(shaResult, 32);
}

bool isPinSet() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    bool res = SPIFFS.exists("/pin.txt");
    xSemaphoreGive(storageMutex);
    return res;
}

bool createPin(const String &pin) {
    if (pin.length() < getMinPinLength()) {
        return false;
    }
    String hashedPin = hashPin(pin);
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/pin.txt", "w");
    if (file) {
        file.print(hashedPin);
        file.close();
    }
    xSemaphoreGive(storageMutex);
    return true;
}

int getFailedPinAttempts() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (!SPIFFS.exists("/failures.txt")) {
        xSemaphoreGive(storageMutex);
        return 0;
    }
    File file = SPIFFS.open("/failures.txt", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return 0;
    }
    String val = file.readString();
    file.close();
    xSemaphoreGive(storageMutex);
    return val.toInt();
}

void incrementFailedPinAttempts() {
    int attempts = getFailedPinAttempts() + 1;
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/failures.txt", "w");
    if (file) {
        file.print(attempts);
        file.close();
    }
    xSemaphoreGive(storageMutex);
}

void resetFailedPinAttempts() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (SPIFFS.exists("/failures.txt")) {
        SPIFFS.remove("/failures.txt");
    }
    xSemaphoreGive(storageMutex);
}

void factoryResetSystem() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    SPIFFS.remove("/passwords.json");
    SPIFFS.remove("/passkeys.json");
    SPIFFS.remove("/passkeys.bin");
    SPIFFS.remove("/passkeys.tmp");
    SPIFFS.remove("/totp.json");
    SPIFFS.remove("/pin.txt");
    SPIFFS.remove("/failures.txt");
    SPIFFS.remove("/crypto_alg.txt");
    SPIFFS.remove("/largeblob.bin");
    SPIFFS.remove("/fido_uv_fail.txt");
    SPIFFS.remove("/fido_force_pin.txt");
    SPIFFS.remove("/fido_min_pin.txt");
    SPIFFS.remove("/bio_templates.json");
    xSemaphoreGive(storageMutex);

    deleteAllFingerprints();
}

bool getLargeBlobArray(uint8_t** outData, size_t &outLen) {
    *outData = nullptr;
    outLen = 0;

    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (!SPIFFS.exists("/largeblob.bin")) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    File file = SPIFFS.open("/largeblob.bin", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }

    size_t sz = file.size();
    uint8_t* buf = (uint8_t*)malloc(sz > 0 ? sz : 1);
    if (!buf) {
        file.close();
        xSemaphoreGive(storageMutex);
        return false;
    }
    file.read(buf, sz);
    file.close();
    xSemaphoreGive(storageMutex);

    *outData = buf;
    outLen = sz;
    return true;
}

bool setLargeBlobArray(const uint8_t* data, size_t len) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/largeblob.bin", "w");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    size_t written = (len > 0) ? file.write(data, len) : 0;
    file.close();
    xSemaphoreGive(storageMutex);
    return written == len;
}

bool deletePin() {
    if (isPinSet()) {
        factoryResetSystem();
        return true;
    }
    return false;
}

bool verifyPin(const String &pin) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/pin.txt", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    String storedHash = file.readString();
    file.close();
    xSemaphoreGive(storageMutex);

    if (storedHash == hashPin(pin)) {
        resetFailedPinAttempts();
        return true;
    } else {
        incrementFailedPinAttempts();
        int totalFailures = getFailedPinAttempts();
        if (totalFailures >= 10) {
            CommsManager::sendError("SECURITY", "MAX_ATTEMPTS_EXCEEDED", "Maximum PIN attempts reached. Device wiped.");
            factoryResetSystem();
            ESP.restart();
        } else {
            CommsManager::sendError("SECURITY", "BAD_PIN_ATTEMPT", String(totalFailures) + "/10 attempts used.");
        }
        return false;
    }
}

bool isPasswordExists(const String &website, const String &login) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (!SPIFFS.exists("/passwords.json")) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    File file = SPIFFS.open("/passwords.json", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    JsonDocument doc;
    DeserializationError error = deserializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);
    return !error && doc[website].is<JsonObject>() && doc[website][login].is<JsonVariant>();
}

bool savePassword(const String &website, const String &login, const String &password) {
    if (!isStorageKeyLoaded) { CommsManager::sendError("PASS", "KEY_LOCKED", "Storage key is not unlocked."); return false; }
    if (website.length() > 64 || login.length() > 64) { CommsManager::sendError("PASS", "IDENTIFIER_TOO_LONG", "Website or login parameter is too long."); return false; }
    if (password.length() > 4000) { CommsManager::sendError("PASS", "PASS_TOO_LONG", "Password length exceeds limits."); return false; }
    if (isPasswordExists(website, login)) { CommsManager::sendError("PASS", "ALREADY_EXISTS", "Credential record already exists."); return false; }

    xSemaphoreTake(storageMutex, portMAX_DELAY);
    JsonDocument doc;
    if (SPIFFS.exists("/passwords.json")) {
        File file = SPIFFS.open("/passwords.json", "r");
        if (file) {
            deserializeJson(doc, file);
            file.close();
        }
    }

    int totalLogins = 0;
    for (JsonPair sitePair : doc.as<JsonObject>()) {
        totalLogins += sitePair.value().as<JsonObject>().size();
    }
    if (totalLogins >= 1000) {
        xSemaphoreGive(storageMutex);
        CommsManager::sendError("PASS", "MAX_LIMIT_REACHED", "Vault capacity reached.");
        return false;
    }

    String encryptedValue = encryptStoragePayload(password, storageKey);
    if (encryptedValue == "") {
        xSemaphoreGive(storageMutex);
        CommsManager::sendError("PASS", "ENC_FAILED", "Failed to encrypt password payload.");
        return false;
    }

    JsonObject siteObj = doc[website].is<JsonObject>() ? doc[website].as<JsonObject>() : doc[website].to<JsonObject>();
    siteObj[login] = encryptedValue;

    File file = SPIFFS.open("/passwords.json", "w");
    if (!file) {
        xSemaphoreGive(storageMutex);
        CommsManager::sendError("PASS", "FILE_CREATE_FAILED", "Unable to open vault storage file.");
        return false;
    }
    serializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);
    return true;
}

String getPasswordFromStorage(const String &website, const String &login) {
    if (!isStorageKeyLoaded) return "";
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/passwords.json", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return "";
    }
    JsonDocument doc;
    deserializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);

    if (!doc[website].is<JsonObject>() || !doc[website][login].is<JsonVariant>()) return "";
    String encryptedValue = doc[website][login].as<String>();
    return decryptStoragePayload(encryptedValue, storageKey);
}

bool deletePassword(const String &website, const String &login) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (!SPIFFS.exists("/passwords.json")) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    File file = SPIFFS.open("/passwords.json", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    JsonDocument doc;
    deserializeJson(doc, file);
    file.close();

    if (!doc[website].is<JsonObject>() || !doc[website][login].is<JsonVariant>()) {
        xSemaphoreGive(storageMutex);
        return false;
    }

    doc[website].as<JsonObject>().remove(login);
    if (doc[website].as<JsonObject>().size() == 0) {
        doc.remove(website);
    }

    file = SPIFFS.open("/passwords.json", "w");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    serializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);
    return true;
}

void listPasswords() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (!SPIFFS.exists("/passwords.json")) {
        xSemaphoreGive(storageMutex);
        JsonDocument data;
        data["items"].to<JsonArray>();
        CommsManager::sendEvent("PASS", "LIST", &data);
        return;
    }
    File file = SPIFFS.open("/passwords.json", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        CommsManager::sendError("PASS", "READ_FAILED", "Failed to open passwords file.");
        return;
    }
    JsonDocument doc;
    DeserializationError error = deserializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);

    if (error) {
        CommsManager::sendError("PASS", "READ_FAILED", "Failed to parse password JSON payload.");
        return;
    }

    std::vector<String> websites;
    std::vector<String> logins;
    std::vector<String> passwords;

    for (JsonPair sitePair : doc.as<JsonObject>()) {
        String website = sitePair.key().c_str();
        JsonObject lgs = sitePair.value().as<JsonObject>();
        for (JsonPair loginPair : lgs) {
            websites.push_back(website);
            logins.push_back(loginPair.key().c_str());
            passwords.push_back(decryptStoragePayload(loginPair.value().as<String>(), storageKey));
        }
    }

    JsonDocument responseData;
    JsonArray itemsArray = responseData["items"].to<JsonArray>();

    for (size_t i = 0; i < websites.size(); i++) {
        String pwd = passwords[i];
        bool isWeak = false;

        if (pwd.length() < 12) {
            isWeak = true;
        } else {
            bool hasNum = false, hasUpper = false, hasLower = false, hasSpec = false;
            for (int c = 0; c < pwd.length(); c++) {
                char ch = pwd[c];
                if (isdigit(ch)) hasNum = true;
                else if (isupper(ch)) hasUpper = true;
                else if (islower(ch)) hasLower = true;
                else hasSpec = true;
            }
            if (!hasNum || !hasUpper || !hasLower || !hasSpec) isWeak = true;
        }

        int freq = 0;
        for (size_t j = 0; j < passwords.size(); j++) {
            if (passwords[j] == pwd) freq++;
        }
        if (freq > 1) isWeak = true;

        JsonObject item = itemsArray.add<JsonObject>();
        item["website"] = websites[i];
        item["login"] = logins[i];
        item["status"] = isWeak ? "WEAK" : "OK";
    }

    for (size_t i = 0; i < passwords.size(); i++) {
        if (passwords[i].length() > 0) {
            memset(const_cast<char*>(passwords[i].c_str()), 0, passwords[i].length());
            passwords[i] = "";
        }
    }

    CommsManager::sendEvent("PASS", "LIST", &responseData);
}

void showStorageInfo() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    size_t total = SPIFFS.totalBytes();
    size_t used = SPIFFS.usedBytes();
    size_t free = total - used;
    float usage = ((float)used / total) * 100;

    int count = 0; size_t chars = 0; float avg = 0;
    if (SPIFFS.exists("/passwords.json")) {
        File file = SPIFFS.open("/passwords.json", "r");
        JsonDocument doc;
        if (!deserializeJson(doc, file)) {
            for (JsonPair sitePair : doc.as<JsonObject>()) {
                JsonObject lgs = sitePair.value().as<JsonObject>();
                for (JsonPair loginPair : lgs) {
                    count++;
                    chars += String(loginPair.value().as<const char *>()).length();
                }
            }
            if (count > 0) avg = (float)chars / count;
        }
        file.close();
    }

    int passkeyCount = 0;
    if (SPIFFS.exists("/passkeys.bin")) {
        File file = SPIFFS.open("/passkeys.bin", "r");
        if (file) {
            while (file.available()) {
                uint8_t status;
                if (file.read(&status, 1) != 1) break;
                file.seek(4, SeekCur);

                uint16_t len;
                if (file.read((uint8_t*)&len, 2) == 2) file.seek(len, SeekCur);
                if (file.read((uint8_t*)&len, 2) == 2) file.seek(len, SeekCur);
                if (file.read((uint8_t*)&len, 2) == 2) file.seek(len, SeekCur);

                if (status == 1) {
                    passkeyCount++;
                }
            }
            file.close();
        }
    }
    xSemaphoreGive(storageMutex);

    JsonDocument data;
    data["total_bytes"] = total;
    data["used_bytes"] = used;
    data["free_bytes"] = free;
    data["usage_percent"] = usage;
    data["passwords_count"] = count;
    data["avg_login_length"] = avg;
    data["passkeys_count"] = passkeyCount;

    CommsManager::sendEvent("STORAGE", "STATS", &data);
}

void clearAllStoredPasswords() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (SPIFFS.exists("/passwords.json")) {
        SPIFFS.remove("/passwords.json");
    }
    if (SPIFFS.exists("/passkeys.json")) {
        SPIFFS.remove("/passkeys.json");
    }
    if (SPIFFS.exists("/passkeys.bin")) {
        SPIFFS.remove("/passkeys.bin");
    }
    xSemaphoreGive(storageMutex);
    clearStorageKey();
    CommsManager::sendEvent("STORAGE", "PURGE_COMPLETE");
}

bool isPasskeyExists(const String &credentialIdHex) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/passkeys.bin", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    bool found = false;
    while (file.available()) {
        PasskeyFrame f;
        if (!readPasskeyFrame(file, f)) break;
        file.seek(f.payLen, SeekCur);
        if (f.status == 1 && f.cid == credentialIdHex) {
            found = true;
            break;
        }
    }
    file.close();
    xSemaphoreGive(storageMutex);
    return found;
}

bool savePasskeyRecord(const String &credentialIdHex, const String &rpId, const String &userIdHex, const String &userName, const String &privateKeyHex, int algId, int credProtect, const String &largeBlobKeyHex, const String &credBlobHex) {
    byte fidoKey[32];
    getFidoHardwareKey(fidoKey);
    String rawPayload = buildPasskeyPayload(userIdHex, userName, privateKeyHex, credProtect, largeBlobKeyHex, credBlobHex);
    String encryptedPayload = encryptStoragePayload(rawPayload, fidoKey);
    secureWipe(rawPayload);

    if (encryptedPayload == "") {
        CommsManager::sendError("FIDO2", "PASSKEY_ENC_FAILED", "Failed to encrypt passkey.");
        return false;
    }

    if (credentialIdHex.length() == 0 || credentialIdHex.length() > 0xFFFF ||
        rpId.length() > 0xFFFF || encryptedPayload.length() > 0xFFFF) {
        CommsManager::sendError("FIDO2", "PASSKEY_TOO_LARGE", "Passkey record field exceeds format limits.");
        return false;
    }

    std::vector<uint8_t> record;
    record.reserve(11 + credentialIdHex.length() + rpId.length() + encryptedPayload.length());
    appendPasskeyFrame(record, 1, (int32_t)algId, credentialIdHex, rpId, encryptedPayload);

    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/passkeys.bin", "a");
    if (!file) {
        xSemaphoreGive(storageMutex);
        CommsManager::sendError("FIDO2", "FILE_CREATE_FAILED", "Failed to open passkeys file.");
        return false;
    }
    size_t written = file.write(record.data(), record.size());
    file.close();
    xSemaphoreGive(storageMutex);
    if (written != record.size()) {
        CommsManager::sendError("FIDO2", "FILE_WRITE_FAILED", "Failed to write passkey record.");
        return false;
    }
    CommsManager::sendEvent("FIDO2", "PASSKEY_SAVED");
    return true;
}

bool savePasskeyRecord(const String &credentialIdHex, const String &rpId, const String &userIdHex, const String &userName, const String &privateKeyHex, int algId, int credProtect, const String &largeBlobKeyHex) {
    return savePasskeyRecord(credentialIdHex, rpId, userIdHex, userName, privateKeyHex, algId, credProtect, largeBlobKeyHex, "");
}

bool savePasskeyRecord(const String &credentialIdHex, const String &rpId, const String &userIdHex, const String &userName, const String &privateKeyHex, int algId) {
    return savePasskeyRecord(credentialIdHex, rpId, userIdHex, userName, privateKeyHex, algId, 1, "", "");
}

bool getPasskeyRecord(const String &credentialIdHex, String &rpIdOut, String &userIdHexOut, String &userNameOut, String &privateKeyHexOut, int &algId, int &credProtectOut, String &largeBlobKeyHexOut, String &credBlobHexOut) {
    byte fidoKey[32];
    getFidoHardwareKey(fidoKey);

    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/passkeys.bin", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }

    bool found = false;
    String encryptedPayload = "";

    while (file.available()) {
        PasskeyFrame f;
        if (!readPasskeyFrame(file, f)) break;
        if (f.status == 1 && f.cid == credentialIdHex) {
            readPayloadString(file, f.payLen, encryptedPayload);
            rpIdOut = f.rp;
            algId = f.algId;
            found = true;
            break;
        }
        file.seek(f.payLen, SeekCur);
    }
    file.close();
    xSemaphoreGive(storageMutex);

    if (!found || encryptedPayload == "") return false;

    String decryptedPayload = decryptStoragePayload(encryptedPayload, fidoKey);
    if (decryptedPayload == "") return false;

    PasskeyPayload parsed;
    bool parsedOk = parsePasskeyPayload(decryptedPayload, parsed);
    secureWipe(decryptedPayload);
    if (!parsedOk) return false;

    userIdHexOut = parsed.userIdHex;
    userNameOut = parsed.userName;
    privateKeyHexOut = parsed.privateKeyHex;
    credProtectOut = parsed.credProtect;
    largeBlobKeyHexOut = parsed.largeBlobKeyHex;
    credBlobHexOut = parsed.credBlobHex;
    return true;
}

bool getPasskeyRecord(const String &credentialIdHex, String &rpIdOut, String &userIdHexOut, String &userNameOut, String &privateKeyHexOut, int &algId, int &credProtectOut, String &largeBlobKeyHexOut) {
    String dummyCredBlobHex;
    return getPasskeyRecord(credentialIdHex, rpIdOut, userIdHexOut, userNameOut, privateKeyHexOut, algId, credProtectOut, largeBlobKeyHexOut, dummyCredBlobHex);
}

bool getPasskeyRecord(const String &credentialIdHex, String &rpIdOut, String &userIdHexOut, String &userNameOut, String &privateKeyHexOut, int &algId) {
    int dummyCredProtect;
    String dummyLargeBlobKeyHex;
    String dummyCredBlobHex;
    return getPasskeyRecord(credentialIdHex, rpIdOut, userIdHexOut, userNameOut, privateKeyHexOut, algId, dummyCredProtect, dummyLargeBlobKeyHex, dummyCredBlobHex);
}

String findCredentialIdByRpAndUser(const String &rpId, const String &userIdHex) {
    byte fidoKey[32];
    getFidoHardwareKey(fidoKey);

    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/passkeys.bin", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return "";
    }

    String foundCid = "";
    while (file.available()) {
        PasskeyFrame f;
        if (!readPasskeyFrame(file, f)) break;
        if (f.status == 1 && rpFieldMatchesRpId(f.rp, rpId)) {
            String encryptedPayload;
            if (readPayloadString(file, f.payLen, encryptedPayload)) {
                String decryptedPayload = decryptStoragePayload(encryptedPayload, fidoKey);
                PasskeyPayload rec;
                if (decryptedPayload != "" && parsePasskeyPayload(decryptedPayload, rec)) {
                    if (userIdHex == "" || rec.userIdHex == userIdHex) {
                        foundCid = f.cid;
                        break;
                    }
                }
            }
        } else {
            file.seek(f.payLen, SeekCur);
        }
    }
    file.close();
    xSemaphoreGive(storageMutex);
    return foundCid;
}

size_t getBinaryCredentialId(const String &rpId, const String &userIdHex, uint8_t* outBuffer, size_t maxOutLen) {
    String credentialIdHex = findCredentialIdByRpAndUser(rpId, userIdHex);
    if (credentialIdHex.length() == 0) {
        return 0;
    }
    size_t binIdLen = credentialIdHex.length() / 2;
    if (binIdLen > maxOutLen) {
        return 0;
    }
    fromHex(credentialIdHex, outBuffer, binIdLen);
    return binIdLen;
}

static const size_t MAX_DISCOVERABLE_CREDENTIALS = 1000;

void listFidoWebsites() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/passkeys.bin", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        JsonDocument data;
        data["websites"].to<JsonArray>();
        data["discoverable_credentials_used"] = 0;
        data["discoverable_credentials_remaining"] = MAX_DISCOVERABLE_CREDENTIALS;
        CommsManager::sendEvent("FIDO2", "LIST", &data);
        return;
    }

    std::vector<String> rpIds;
    size_t credentialCount = 0;
    while (file.available()) {
        PasskeyFrame f;
        if (!readPasskeyFrame(file, f)) break;
        file.seek(f.payLen, SeekCur);
        if (f.status == 1) {
            credentialCount++;
            bool exists = false;
            for (const String &r : rpIds) {
                if (r == f.rp) { exists = true; break; }
            }
            if (!exists) rpIds.push_back(f.rp);
        }
    }
    file.close();
    xSemaphoreGive(storageMutex);

    JsonDocument responseData;
    JsonArray websitesArray = responseData["websites"].to<JsonArray>();
    for (const String &rp : rpIds) {
        websitesArray.add(rp);
    }

    size_t remaining = (credentialCount >= MAX_DISCOVERABLE_CREDENTIALS)
                            ? 0
                            : (MAX_DISCOVERABLE_CREDENTIALS - credentialCount);
    responseData["discoverable_credentials_used"] = credentialCount;
    responseData["discoverable_credentials_remaining"] = remaining;

    CommsManager::sendEvent("FIDO2", "LIST", &responseData);
}

bool deleteFidoWebsite(const String &rpId) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/passkeys.bin", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }

    std::vector<uint8_t> kept;
    bool deletedAny = false;
    while (file.available()) {
        PasskeyFrame f;
        if (!readPasskeyFrame(file, f)) break;
        String pay;
        if (!readPayloadString(file, f.payLen, pay)) break;
        if (f.status == 1 && f.rp == rpId) {
            deletedAny = true;
        } else if (f.status == 1) {
            appendPasskeyFrame(kept, 1, f.algId, f.cid, f.rp, pay);
        }
    }
    file.close();

    bool ok = deletedAny && replacePasskeyFile(kept);
    xSemaphoreGive(storageMutex);
    return ok;
}

String getFidoWebsiteInfo(const String &rpId) {
    byte fidoKey[32];
    getFidoHardwareKey(fidoKey);
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/passkeys.bin", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return "";
    }

    String result = "";
    while (file.available()) {
        PasskeyFrame f;
        if (!readPasskeyFrame(file, f)) break;
        if (f.status == 1 && f.rp == rpId) {
            String encryptedPayload;
            if (readPayloadString(file, f.payLen, encryptedPayload)) {
                String decryptedPayload = decryptStoragePayload(encryptedPayload, fidoKey);
                PasskeyPayload rec;
                if (decryptedPayload != "" && parsePasskeyPayload(decryptedPayload, rec)) {
                    result += rec.userName + " | CRED_ID:" + f.cid + "\n";
                }
            }
        } else {
            file.seek(f.payLen, SeekCur);
        }
    }
    file.close();
    xSemaphoreGive(storageMutex);
    return result;
}

void saveTotpSecret(const String &name, const String &secret) {
    if (!isStorageKeyLoaded) return;

    xSemaphoreTake(storageMutex, portMAX_DELAY);
    JsonDocument doc;
    if (SPIFFS.exists("/totp.json")) {
        File file = SPIFFS.open("/totp.json", "r");
        if (file) {
            deserializeJson(doc, file);
            file.close();
        }
    }

    String encryptedValue = encryptStoragePayload(secret, storageKey);
    if (encryptedValue == "") {
        xSemaphoreGive(storageMutex);
        CommsManager::sendError("TOTP", "ENC_FAILED", "Failed to encrypt secret.");
        return;
    }

    doc[name] = encryptedValue;
    File file = SPIFFS.open("/totp.json", "w");
    if (!file) {
        xSemaphoreGive(storageMutex);
        CommsManager::sendError("TOTP", "FILE_WRITE_FAILED", "Unable to save secret.");
        return;
    }

    serializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);
    CommsManager::sendEvent("TOTP", "SAVED");
}

String getTotpSecret(const String &name) {
    if (!isStorageKeyLoaded) return "";

    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/totp.json", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return "";
    }

    JsonDocument doc;
    deserializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);

    if (!doc[name].is<JsonVariant>()) return "";

    String encryptedValue = doc[name].as<String>();
    return decryptStoragePayload(encryptedValue, storageKey);
}

void saveDefaultCryptoAlg(int algId) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/crypto_alg.txt", "w");
    if (file) {
        file.print(algId);
        file.close();
    }
    xSemaphoreGive(storageMutex);
}

int loadDefaultCryptoAlg() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (!SPIFFS.exists("/crypto_alg.txt")) {
        xSemaphoreGive(storageMutex);
        return -7;
    }
    File file = SPIFFS.open("/crypto_alg.txt", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return -7;
    }
    String val = file.readString();
    file.close();
    xSemaphoreGive(storageMutex);
    return val.toInt();
}

void handleTotpGetAll(uint32_t currentEpoch) {
    if (!isStorageKeyLoaded || !SPIFFS.exists("/totp.json")) {
        JsonDocument data;
        data["codes"].to<JsonObject>();
        CommsManager::sendEvent("TOTP", "CODES", &data);
        return;
    }

    File file = SPIFFS.open("/totp.json", "r");
    JsonDocument doc;
    JsonDocument responseData;
    JsonObject codesObj = responseData["codes"].to<JsonObject>();

    if (deserializeJson(doc, file) == DeserializationError::Ok) {
        JsonObject obj = doc.as<JsonObject>();
        for (JsonPair pair : obj) {
            const char* accountName = pair.key().c_str();
            String encryptedValue = pair.value().as<String>();

            String decryptedSecret = decryptStoragePayload(encryptedValue, storageKey);
            if (decryptedSecret != "") {
                String codeStr = generateTOTP(decryptedSecret, currentEpoch);
                codesObj[accountName] = codeStr;
            }
        }
    }
    file.close();
    CommsManager::sendEvent("TOTP", "CODES", &responseData);
}

bool deleteTotpSecret(const String &name) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (!SPIFFS.exists("/totp.json")) {
        xSemaphoreGive(storageMutex);
        return false;
    }

    File file = SPIFFS.open("/totp.json", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }

    JsonDocument doc;
    deserializeJson(doc, file);
    file.close();

    if (!doc[name].is<JsonVariant>()) {
        xSemaphoreGive(storageMutex);
        return false;
    }

    doc.remove(name);

    file = SPIFFS.open("/totp.json", "w");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }

    serializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);

    return true;
}

bool exportVaultPlaintext(JsonDocument &out) {
    if (!isStorageKeyLoaded) return false;

    JsonArray passwordsArr = out["passwords"].to<JsonArray>();
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (SPIFFS.exists("/passwords.json")) {
        File file = SPIFFS.open("/passwords.json", "r");
        if (file) {
            JsonDocument doc;
            if (deserializeJson(doc, file) == DeserializationError::Ok) {
                for (JsonPair sitePair : doc.as<JsonObject>()) {
                    String website = sitePair.key().c_str();
                    JsonObject lgs = sitePair.value().as<JsonObject>();
                    for (JsonPair loginPair : lgs) {
                        String plain = decryptStoragePayload(loginPair.value().as<String>(), storageKey);
                        if (plain.length() == 0) continue;
                        JsonObject item = passwordsArr.add<JsonObject>();
                        item["site"] = website;
                        item["login"] = loginPair.key().c_str();
                        item["password"] = plain;
                    }
                }
            }
            file.close();
        }
    }
    xSemaphoreGive(storageMutex);

    JsonArray totpArr = out["totp"].to<JsonArray>();
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (SPIFFS.exists("/totp.json")) {
        File file = SPIFFS.open("/totp.json", "r");
        if (file) {
            JsonDocument doc;
            if (deserializeJson(doc, file) == DeserializationError::Ok) {
                for (JsonPair pair : doc.as<JsonObject>()) {
                    String plain = decryptStoragePayload(pair.value().as<String>(), storageKey);
                    if (plain.length() == 0) continue;
                    JsonObject item = totpArr.add<JsonObject>();
                    item["name"] = pair.key().c_str();
                    item["secret"] = plain;
                }
            }
            file.close();
        }
    }
    xSemaphoreGive(storageMutex);

    out["crypto_alg"] = loadDefaultCryptoAlg();
    out["backup_format"] = 1;
    return true;
}

bool importVaultPlaintext(JsonDocument &in, bool overwrite, uint32_t &importedCount, uint32_t &skippedCount) {
    importedCount = 0;
    skippedCount = 0;
    if (!isStorageKeyLoaded) return false;

    JsonArray passwordsArr = in["passwords"].as<JsonArray>();
    for (JsonObject item : passwordsArr) {
        String site = item["site"] | "";
        String login = item["login"] | "";
        String pass = item["password"] | "";
        if (site == "" || login == "") { skippedCount++; continue; }

        if (isPasswordExists(site, login)) {
            if (!overwrite) { skippedCount++; continue; }
            deletePassword(site, login);
        }
        if (savePassword(site, login, pass)) {
            importedCount++;
        } else {
            skippedCount++;
        }
    }

    JsonArray totpArr = in["totp"].as<JsonArray>();
    for (JsonObject item : totpArr) {
        String name = item["name"] | "";
        String secret = item["secret"] | "";
        if (name == "" || secret == "") { skippedCount++; continue; }

        bool exists = getTotpSecret(name).length() > 0;
        if (exists && !overwrite) { skippedCount++; continue; }

        saveTotpSecret(name, secret);
        importedCount++;
    }

    if (in["crypto_alg"].is<int>()) {
        saveDefaultCryptoAlg(in["crypto_alg"].as<int>());
    }

    return true;
}

static const uint8_t MAX_BIO_TEMPLATES = 127;

std::vector<uint8_t> getAllBioTemplateIds() {
    std::vector<uint8_t> ids;
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (SPIFFS.exists("/bio_templates.json")) {
        File file = SPIFFS.open("/bio_templates.json", "r");
        if (file) {
            JsonDocument doc;
            if (deserializeJson(doc, file) == DeserializationError::Ok) {
                JsonObject obj = doc.as<JsonObject>();
                for (JsonPair pair : obj) {
                    ids.push_back((uint8_t)atoi(pair.key().c_str()));
                }
            }
            file.close();
        }
    }
    xSemaphoreGive(storageMutex);
    return ids;
}

int getBioTemplateCount() {
    return (int)getAllBioTemplateIds().size();
}

uint8_t findFreeBioTemplateSlot() {
    std::vector<uint8_t> used = getAllBioTemplateIds();
    for (uint8_t id = 1; id < MAX_BIO_TEMPLATES; id++) {
        bool taken = false;
        for (uint8_t u : used) {
            if (u == id) { taken = true; break; }
        }
        if (!taken) return id;
    }
    return 0;
}

bool saveBioTemplateName(uint8_t templateId, const String &friendlyName) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);

    JsonDocument doc;
    if (SPIFFS.exists("/bio_templates.json")) {
        File file = SPIFFS.open("/bio_templates.json", "r");
        if (file) {
            deserializeJson(doc, file);
            file.close();
        }
    }

    doc[String(templateId)] = friendlyName;

    File file = SPIFFS.open("/bio_templates.json", "w");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    serializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);
    return true;
}

String getBioTemplateName(uint8_t templateId) {
    String result = "";
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (SPIFFS.exists("/bio_templates.json")) {
        File file = SPIFFS.open("/bio_templates.json", "r");
        if (file) {
            JsonDocument doc;
            if (deserializeJson(doc, file) == DeserializationError::Ok) {
                String key = String(templateId);
                if (doc[key].is<JsonVariant>()) {
                    result = doc[key].as<String>();
                }
            }
            file.close();
        }
    }
    xSemaphoreGive(storageMutex);
    return result;
}

bool deleteBioTemplateRecord(uint8_t templateId) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (!SPIFFS.exists("/bio_templates.json")) {
        xSemaphoreGive(storageMutex);
        return false;
    }

    File file = SPIFFS.open("/bio_templates.json", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    JsonDocument doc;
    deserializeJson(doc, file);
    file.close();

    String key = String(templateId);
    if (!doc[key].is<JsonVariant>()) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    doc.remove(key);

    file = SPIFFS.open("/bio_templates.json", "w");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }
    serializeJson(doc, file);
    file.close();
    xSemaphoreGive(storageMutex);
    return true;
}

void secureWipe(String &str) {
    if (str.length() > 0) {
        memset(const_cast<char*>(str.c_str()), 0, str.length());
        str = "";
    }
}

bool isFidoPinSet() {
    return isPinSet();
}

bool createFidoPin(const String &pin) {
    return createPin(pin);
}

int getFailedFidoPinAttempts() {
    return getFailedPinAttempts();
}

void resetFido2System() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    SPIFFS.remove("/passwords.json");
    SPIFFS.remove("/passkeys.json");
    SPIFFS.remove("/passkeys.bin");
    SPIFFS.remove("/passkeys.tmp");
    SPIFFS.remove("/totp.json");
    SPIFFS.remove("/pin.txt");
    SPIFFS.remove("/failures.txt");
    SPIFFS.remove("/crypto_alg.txt");
    SPIFFS.remove("/fido_uv_fail.txt");
    SPIFFS.remove("/fido_force_pin.txt");
    SPIFFS.remove("/fido_min_pin.txt");
    SPIFFS.remove("/largeblob.bin");
    SPIFFS.remove("/bio_templates.json");
    rotateStatelessMasterSecret();
    xSemaphoreGive(storageMutex);
    
    clearStorageKey();
    authenticated = false;
    currentCommandState = STATE_READY;
    
    deleteAllFingerprints();
    
    CommsManager::sendEvent("FIDO2", "RESET_COMPLETE");
}

std::vector<String> findAllCredentialsByRp(const String &rpId) {
    std::vector<String> results;
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/passkeys.bin", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return results;
    }
    while (file.available()) {
        PasskeyFrame f;
        if (!readPasskeyFrame(file, f)) break;
        file.seek(f.payLen, SeekCur);
        if (f.status == 1 && rpFieldMatchesRpId(f.rp, rpId)) {
            results.push_back(f.cid);
        }
    }
    file.close();
    xSemaphoreGive(storageMutex);
    return results;
}

std::vector<String> getAllStoredCredentialIds() {
    std::vector<String> results;
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/passkeys.bin", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return results;
    }
    while (file.available()) {
        PasskeyFrame f;
        if (!readPasskeyFrame(file, f)) break;
        file.seek(f.payLen, SeekCur);
        if (f.status == 1) {
            results.push_back(f.cid);
        }
    }
    file.close();
    xSemaphoreGive(storageMutex);
    return results;
}

std::vector<String> getAllStoredRpIds() {
    std::vector<String> results;
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/passkeys.bin", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return results;
    }
    while (file.available()) {
        PasskeyFrame f;
        if (!readPasskeyFrame(file, f)) break;
        file.seek(f.payLen, SeekCur);
        if (f.status == 1) {
            bool exists = false;
            for (const String &r : results) {
                if (r == f.rp) { exists = true; break; }
            }
            if (!exists) results.push_back(f.rp);
        }
    }
    file.close();
    xSemaphoreGive(storageMutex);
    return results;
}

bool deletePasskeyRecord(const String &credentialIdHex) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/passkeys.bin", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return false;
    }

    std::vector<uint8_t> kept;
    bool deleted = false;
    while (file.available()) {
        PasskeyFrame f;
        if (!readPasskeyFrame(file, f)) break;
        String pay;
        if (!readPayloadString(file, f.payLen, pay)) break;
        if (f.status == 1 && f.cid == credentialIdHex) {
            deleted = true;
        } else if (f.status == 1) {
            appendPasskeyFrame(kept, 1, f.algId, f.cid, f.rp, pay);
        }
    }
    file.close();

    bool ok = deleted && replacePasskeyFile(kept);
    xSemaphoreGive(storageMutex);
    return ok;
}

static void getStatelessMasterKeys(uint8_t* aesKey, uint8_t* hmacKey) {
    uint8_t secret[32];
    getStatelessMasterSecret(secret);

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);

    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, secret, 32);
    mbedtls_md_update(&ctx, (const uint8_t*)"STATELESS_AES_KEY_SALT", 22);
    mbedtls_md_finish(&ctx, aesKey);

    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, secret, 32);
    mbedtls_md_update(&ctx, (const uint8_t*)"STATELESS_HMAC_KEY_SALT", 23);
    mbedtls_md_finish(&ctx, hmacKey);

    mbedtls_md_free(&ctx);
}

static const size_t STATELESS_MAX_USER_ID = 64;
static const size_t STATELESS_MAX_NAME = 32;
static const size_t STATELESS_V1_HEADER = 108;

static size_t utf8SafeLength(const String &s, size_t maxBytes) {
    size_t len = s.length();
    if (len <= maxBytes) return len;
    size_t cut = maxBytes;
    while (cut > 0 && (((uint8_t)s[cut]) & 0xC0) == 0x80) cut--;
    return cut;
}

static void sha256Of(const uint8_t *data, size_t len, uint8_t out[32]) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, data, len);
    mbedtls_md_finish(&ctx, out);
    mbedtls_md_free(&ctx);
}

bool wrapStatelessCredential(const String &rpId, const uint8_t *userId, size_t userIdLen,
                             const String &userName, const String &privateKeyHex, int algId,
                             uint8_t *outCredId, size_t outCapacity, size_t &outCredIdLen) {
    outCredIdLen = 0;
    if (!outCredId) return false;
    if (userIdLen > STATELESS_MAX_USER_ID || (userIdLen > 0 && !userId)) return false;
    if (privateKeyHex.length() == 0 || privateKeyHex.length() % 2 != 0 || privateKeyHex.length() / 2 > 0xFFFF) return false;

    size_t privLen = privateKeyHex.length() / 2;
    size_t nameLen = utf8SafeLength(userName, STATELESS_MAX_NAME);
    size_t plainLen = 4 + 4 + 32 + 1 + userIdLen + 1 + nameLen + 2 + privLen;
    size_t paddedLen = (plainLen + 15) & ~(size_t)15;
    if (16 + paddedLen + 32 > outCapacity) return false;

    uint8_t aesKey[32], hmacKey[32];
    getStatelessMasterKeys(aesKey, hmacKey);

    uint8_t* plaintext = (uint8_t*)calloc(1, paddedLen);
    if (!plaintext) { secureZero(aesKey, 32); secureZero(hmacKey, 32); return false; }

    size_t off = 0;
    memcpy(&plaintext[off], "STA2", 4); off += 4;
    int32_t netAlg = (int32_t)algId;
    plaintext[off++] = (netAlg >> 24) & 0xFF;
    plaintext[off++] = (netAlg >> 16) & 0xFF;
    plaintext[off++] = (netAlg >> 8) & 0xFF;
    plaintext[off++] = netAlg & 0xFF;
    sha256Of((const uint8_t*)rpId.c_str(), rpId.length(), &plaintext[off]); off += 32;
    plaintext[off++] = (uint8_t)userIdLen;
    if (userIdLen > 0) memcpy(&plaintext[off], userId, userIdLen);
    off += userIdLen;
    plaintext[off++] = (uint8_t)nameLen;
    memcpy(&plaintext[off], userName.c_str(), nameLen); off += nameLen;
    plaintext[off++] = (privLen >> 8) & 0xFF;
    plaintext[off++] = privLen & 0xFF;
    if (!hexDecodeStrict(privateKeyHex, &plaintext[off], privLen)) {
        secureZero(plaintext, paddedLen); free(plaintext);
        secureZero(aesKey, 32); secureZero(hmacKey, 32);
        return false;
    }

    uint8_t iv[16], iv_copy[16];
    esp_fill_random(iv, 16);
    memcpy(iv_copy, iv, 16);

    uint8_t* encrypted = (uint8_t*)malloc(paddedLen);
    if (!encrypted) {
        secureZero(plaintext, paddedLen); free(plaintext);
        secureZero(aesKey, 32); secureZero(hmacKey, 32);
        return false;
    }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, aesKey, 256);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, paddedLen, iv_copy, plaintext, encrypted);
    mbedtls_aes_free(&aes);

    uint8_t hmac[32];
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&md_ctx, hmacKey, 32);
    mbedtls_md_hmac_update(&md_ctx, iv, 16);
    mbedtls_md_hmac_update(&md_ctx, encrypted, paddedLen);
    mbedtls_md_hmac_finish(&md_ctx, hmac);
    mbedtls_md_free(&md_ctx);

    memcpy(&outCredId[0], iv, 16);
    memcpy(&outCredId[16], encrypted, paddedLen);
    memcpy(&outCredId[16 + paddedLen], hmac, 32);
    outCredIdLen = 16 + paddedLen + 32;

    secureZero(plaintext, paddedLen);
    free(plaintext);
    free(encrypted);
    secureZero(aesKey, 32);
    secureZero(hmacKey, 32);
    return true;
}

bool unwrapStatelessCredential(const uint8_t *credId, size_t credIdLen, const String &rpId,
                               String &outUserIdHex, String &outUserName,
                               String &outPrivateKeyHex, int &outAlgId) {
    if (!credId || credIdLen < 16 + 16 + 32) return false;

    size_t encryptedLen = credIdLen - 48;
    if (encryptedLen % 16 != 0) return false;

    uint8_t aesKey[32], hmacKey[32];
    getStatelessMasterKeys(aesKey, hmacKey);

    const uint8_t* iv = &credId[0];
    const uint8_t* encrypted = &credId[16];
    const uint8_t* expectedHmac = &credId[16 + encryptedLen];

    uint8_t computedHmac[32];
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&md_ctx, hmacKey, 32);
    mbedtls_md_hmac_update(&md_ctx, iv, 16);
    mbedtls_md_hmac_update(&md_ctx, encrypted, encryptedLen);
    mbedtls_md_hmac_finish(&md_ctx, computedHmac);
    mbedtls_md_free(&md_ctx);
    secureZero(hmacKey, 32);

    if (!constantTimeEqual(expectedHmac, computedHmac, 32)) { secureZero(aesKey, 32); return false; }

    uint8_t* plaintext = (uint8_t*)malloc(encryptedLen);
    if (!plaintext) { secureZero(aesKey, 32); return false; }

    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, aesKey, 256);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, encryptedLen, iv_copy, encrypted, plaintext);
    mbedtls_aes_free(&aes);
    secureZero(aesKey, 32);

    bool ok = false;
    uint8_t expectedRpHash[32];
    sha256Of((const uint8_t*)rpId.c_str(), rpId.length(), expectedRpHash);

    bool isV1 = encryptedLen >= 4 && memcmp(plaintext, "STAT", 4) == 0;
    bool isV2 = encryptedLen >= 4 && memcmp(plaintext, "STA2", 4) == 0;

    if (isV1 && encryptedLen >= STATELESS_V1_HEADER && constantTimeEqual(&plaintext[8], expectedRpHash, 32)) {
        uint16_t pLen = (plaintext[106] << 8) | plaintext[107];
        if (STATELESS_V1_HEADER + (size_t)pLen <= encryptedLen) {
            outAlgId = (int)(((int32_t)plaintext[4] << 24) | ((int32_t)plaintext[5] << 16) | ((int32_t)plaintext[6] << 8) | plaintext[7]);
            uint8_t uLen = plaintext[40] > 32 ? 32 : plaintext[40];
            outUserIdHex = toHex(&plaintext[41], uLen);
            uint8_t nLen = plaintext[73] > 32 ? 32 : plaintext[73];
            char nameBuf[33] = {0};
            memcpy(nameBuf, &plaintext[74], nLen);
            outUserName = String(nameBuf);
            outPrivateKeyHex = toHex(&plaintext[108], pLen);
            ok = true;
        }
    } else if (isV2 && encryptedLen >= 4 + 4 + 32 + 1 && constantTimeEqual(&plaintext[8], expectedRpHash, 32)) {
        size_t off = 40;
        size_t uLen = plaintext[off++];
        if (uLen <= STATELESS_MAX_USER_ID && off + uLen + 1 <= encryptedLen) {
            const uint8_t *uid = &plaintext[off];
            off += uLen;
            size_t nLen = plaintext[off++];
            if (nLen <= STATELESS_MAX_NAME && off + nLen + 2 <= encryptedLen) {
                const uint8_t *nm = &plaintext[off];
                off += nLen;
                size_t pLen = ((size_t)plaintext[off] << 8) | plaintext[off + 1];
                off += 2;
                if (pLen > 0 && off + pLen <= encryptedLen) {
                    outAlgId = (int)(((int32_t)plaintext[4] << 24) | ((int32_t)plaintext[5] << 16) | ((int32_t)plaintext[6] << 8) | plaintext[7]);
                    outUserIdHex = toHex(uid, uLen);
                    char nameBuf[STATELESS_MAX_NAME + 1] = {0};
                    memcpy(nameBuf, nm, nLen);
                    outUserName = String(nameBuf);
                    outPrivateKeyHex = toHex(&plaintext[off], pLen);
                    ok = true;
                }
            }
        }
    }

    secureZero(plaintext, encryptedLen);
    free(plaintext);
    return ok;
}

static void getStatelessMasterSecret(uint8_t secretOut[32]) {
    nvs_handle_t h;
    if (nvs_open("storage", NVS_READWRITE, &h) != ESP_OK) {
        memset(secretOut, 0, 32);
        return;
    }
    size_t len = 32;
    if (nvs_get_blob(h, "sl_secret", secretOut, &len) != ESP_OK || len != 32) {
        esp_fill_random(secretOut, 32);
        nvs_set_blob(h, "sl_secret", secretOut, 32);
        nvs_commit(h);
    }
    nvs_close(h);
}

void rotateStatelessMasterSecret() {
    nvs_handle_t h;
    if (nvs_open("storage", NVS_READWRITE, &h) == ESP_OK) {
        uint8_t fresh[32];
        esp_fill_random(fresh, 32);
        nvs_set_blob(h, "sl_secret", fresh, 32);
        nvs_commit(h);
        nvs_close(h);
    }
}

static const size_t ATTESTATION_CHAIN_MAX_LEN = 2048;

bool isAttestationProvisioned() {
    nvs_handle_t h;
    if (nvs_open("fido_attest", NVS_READONLY, &h) != ESP_OK) return false;
    size_t len = 0;
    esp_err_t err = nvs_get_blob(h, "chain", NULL, &len);
    nvs_close(h);
    return err == ESP_OK && len > 0;
}

bool loadAttestationCertChain(uint8_t* buf, size_t bufCap, size_t* outLen) {
    nvs_handle_t h;
    if (nvs_open("fido_attest", NVS_READONLY, &h) != ESP_OK) return false;
    size_t len = bufCap;
    esp_err_t err = nvs_get_blob(h, "chain", buf, &len);
    nvs_close(h);
    if (err != ESP_OK || len == 0) return false;
    *outLen = len;
    return true;
}

bool saveAttestationCertChain(const uint8_t* buf, size_t len) {
    if (len == 0 || len > ATTESTATION_CHAIN_MAX_LEN) return false;
    nvs_handle_t h;
    if (nvs_open("fido_attest", NVS_READWRITE, &h) != ESP_OK) return false;
    esp_err_t err = nvs_set_blob(h, "chain", buf, len);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err == ESP_OK;
}

bool loadAttestationPrivateKey(uint8_t privKeyOut[32]) {
    nvs_handle_t h;
    if (nvs_open("fido_attest", NVS_READONLY, &h) != ESP_OK) return false;
    size_t len = 32;
    esp_err_t err = nvs_get_blob(h, "privkey", privKeyOut, &len);
    nvs_close(h);
    return err == ESP_OK && len == 32;
}

bool saveAttestationPrivateKey(const uint8_t privKey[32]) {
    nvs_handle_t h;
    if (nvs_open("fido_attest", NVS_READWRITE, &h) != ESP_OK) return false;
    esp_err_t err = nvs_set_blob(h, "privkey", privKey, 32);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err == ESP_OK;
}

bool eraseAttestationProvisioning() {
    nvs_handle_t h;
    if (nvs_open("fido_attest", NVS_READWRITE, &h) != ESP_OK) return false;
    nvs_erase_all(h);
    esp_err_t err = nvs_commit(h);
    nvs_close(h);
    return err == ESP_OK;
}

int getFailedUvAttempts() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (!SPIFFS.exists("/fido_uv_fail.txt")) {
        xSemaphoreGive(storageMutex);
        return 0;
    }
    File file = SPIFFS.open("/fido_uv_fail.txt", "r");
    if (!file) {
        xSemaphoreGive(storageMutex);
        return 0;
    }
    String val = file.readString();
    file.close();
    xSemaphoreGive(storageMutex);
    return val.toInt();
}

void incrementFailedUvAttempts() {
    int attempts = getFailedUvAttempts() + 1;
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/fido_uv_fail.txt", "w");
    if (file) {
        file.print(attempts);
        file.close();
    }
    xSemaphoreGive(storageMutex);
}

void resetFailedUvAttempts() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    if (SPIFFS.exists("/fido_uv_fail.txt")) {
        SPIFFS.remove("/fido_uv_fail.txt");
    }
    xSemaphoreGive(storageMutex);
}

bool getForcePinChange() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    bool res = false;
    if (SPIFFS.exists("/fido_force_pin.txt")) {
        File f = SPIFFS.open("/fido_force_pin.txt", "r");
        if (f) {
            res = (f.readString().toInt() == 1);
            f.close();
        }
    }
    xSemaphoreGive(storageMutex);
    return res;
}

void setForcePinChange(bool force) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File f = SPIFFS.open("/fido_force_pin.txt", "w");
    if (f) {
        f.print(force ? "1" : "0");
        f.close();
    }
    xSemaphoreGive(storageMutex);
}

uint8_t getMinPinLength() {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    uint8_t res = 4;
    if (SPIFFS.exists("/fido_min_pin.txt")) {
        File f = SPIFFS.open("/fido_min_pin.txt", "r");
        if (f) {
            res = f.readString().toInt();
            f.close();
        }
    }
    xSemaphoreGive(storageMutex);
    return res < 4 ? 4 : res;
}

void setMinPinLength(uint8_t length) {
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File f = SPIFFS.open("/fido_min_pin.txt", "w");
    if (f) {
        f.print(length);
        f.close();
    }
    xSemaphoreGive(storageMutex);
}

void incrementFailedFidoPinAttempts() {
    incrementFailedPinAttempts();
}

void resetFailedFidoPinAttempts() {
    resetFailedPinAttempts();
}

bool verifyFidoPinInternal(const String& pin) {
    if (!isPinSet()) return false;
    String hashedPin = hashPin(pin);
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/pin.txt", "r");
    String storedHash = "";
    if (file) {
        storedHash = file.readString();
        file.close();
    }
    xSemaphoreGive(storageMutex);
    return storedHash == hashedPin;
}

bool verifyFidoPinHashInternal(const uint8_t pinHash16[16]) {
    if (!isPinSet()) return false;
    xSemaphoreTake(storageMutex, portMAX_DELAY);
    File file = SPIFFS.open("/pin.txt", "r");
    String storedHash = "";
    if (file) {
        storedHash = file.readString();
        file.close();
    }
    xSemaphoreGive(storageMutex);
    if (storedHash.length() < 32) return false;
    uint8_t storedBytes[16];
    fromHex(storedHash.substring(0, 32), storedBytes, 16);
    return memcmp(storedBytes, pinHash16, 16) == 0;
}