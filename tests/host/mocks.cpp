#include "Arduino.h"
#include "SPIFFS.h"
#include "nvs.h"
#include "mbedtls/md.h"
#include "mbedtls/aes.h"
#include "mbedtls/pkcs5.h"
#include "freertos/semphr.h"
#include "CryptoManager.h"
#include "CommsManager.h"
#include "FingerprintManager.h"
#include "host_hooks.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

static std::map<std::string, std::vector<uint8_t>> g_fs;
static std::map<std::string, std::vector<uint8_t>> g_nvs;
static std::map<void *, int> g_lockDepth;
static int g_lockViolations = 0;
static bool g_restarted = false;
static std::vector<std::string> g_events;

std::map<std::string, std::vector<uint8_t>> &host_fs() { return g_fs; }
std::map<std::string, std::vector<uint8_t>> &host_nvs() { return g_nvs; }

void host_reset_environment() {
    g_fs.clear();
    g_nvs.clear();
    g_lockDepth.clear();
    g_lockViolations = 0;
    g_restarted = false;
    g_events.clear();
}
int host_lock_violations() {
    int open = 0;
    for (auto &kv : g_lockDepth) open += kv.second;
    return g_lockViolations + open;
}
bool host_restarted() { return g_restarted; }
std::vector<std::string> &host_events() { return g_events; }

int host_sem_take(SemaphoreHandle_t h) {
    int &d = g_lockDepth[h];
    if (d > 0) g_lockViolations++;
    d++;
    return 1;
}
int host_sem_give(SemaphoreHandle_t h) {
    int &d = g_lockDepth[h];
    if (d <= 0) g_lockViolations++;
    else d--;
    return 1;
}

void EspClass::restart() { g_restarted = true; }
EspClass ESP;
unsigned long millis() { return 0; }
void delay(unsigned long) {}
uint32_t esp_random() { uint32_t v; RAND_bytes((unsigned char *)&v, 4); return v; }
void esp_fill_random(void *buf, size_t len) { RAND_bytes((unsigned char *)buf, (int)len); }

int File::available() { return st && st->valid ? (int)(size() - (st->pos < size() ? st->pos : size())) : 0; }
int File::read() {
    if (!st || !st->valid) return -1;
    auto &d = g_fs[st->path];
    if (st->pos >= d.size()) return -1;
    return d[st->pos++];
}
int File::peek() {
    if (!st || !st->valid) return -1;
    auto &d = g_fs[st->path];
    if (st->pos >= d.size()) return -1;
    return d[st->pos];
}
size_t File::read(uint8_t *buf, size_t n) {
    if (!st || !st->valid) return 0;
    auto &d = g_fs[st->path];
    size_t k = 0;
    while (k < n && st->pos < d.size()) buf[k++] = d[st->pos++];
    return k;
}
size_t File::write(uint8_t c) { return write(&c, 1); }
size_t File::write(const uint8_t *buf, size_t n) {
    if (!st || !st->valid || !st->writable) return 0;
    auto &d = g_fs[st->path];
    if (st->pos > d.size()) d.resize(st->pos);
    for (size_t i = 0; i < n; i++) {
        if (st->pos < d.size()) d[st->pos] = buf[i];
        else d.push_back(buf[i]);
        st->pos++;
    }
    return n;
}
bool File::seek(uint32_t pos, SeekMode mode) {
    if (!st || !st->valid) return false;
    size_t sz = g_fs[st->path].size();
    long target = 0;
    if (mode == SeekSet) target = (long)pos;
    else if (mode == SeekCur) target = (long)st->pos + (int32_t)pos;
    else target = (long)sz + (int32_t)pos;
    if (target < 0 || (size_t)target > sz) return false;
    st->pos = (size_t)target;
    return true;
}
size_t File::position() const { return st ? st->pos : 0; }
size_t File::size() const { return st && st->valid ? g_fs[st->path].size() : 0; }
void File::close() { if (st) st->valid = false; }

SPIFFSFS SPIFFS;
bool SPIFFSFS::begin(bool) { return true; }
bool SPIFFSFS::exists(const char *p) { return g_fs.count(p) > 0; }
File SPIFFSFS::open(const char *p, const char *mode) {
    auto s = std::make_shared<HostFileState>();
    s->path = p;
    std::string m = mode;
    if (m == "r") {
        if (!g_fs.count(p)) return File();
        s->valid = true;
    } else if (m == "w") {
        g_fs[p].clear();
        s->valid = true;
        s->writable = true;
    } else if (m == "a") {
        g_fs[p];
        s->valid = true;
        s->writable = true;
        s->pos = g_fs[p].size();
    } else {
        return File();
    }
    return File(s);
}
bool SPIFFSFS::remove(const char *p) { return g_fs.erase(p) > 0; }
bool SPIFFSFS::rename(const char *a, const char *b) {
    if (!g_fs.count(a)) return false;
    g_fs[b] = g_fs[a];
    g_fs.erase(a);
    return true;
}
size_t SPIFFSFS::totalBytes() { return 1500000; }
size_t SPIFFSFS::usedBytes() { size_t n = 0; for (auto &kv : g_fs) n += kv.second.size(); return n; }

esp_err_t nvs_open(const char *, nvs_open_mode_t, nvs_handle_t *h) { *h = 1; return ESP_OK; }
esp_err_t nvs_get_blob(nvs_handle_t, const char *key, void *out, size_t *len) {
    auto it = g_nvs.find(key);
    if (it == g_nvs.end()) return ESP_FAIL;
    if (out && *len >= it->second.size()) memcpy(out, it->second.data(), it->second.size());
    *len = it->second.size();
    return ESP_OK;
}
esp_err_t nvs_set_blob(nvs_handle_t, const char *key, const void *v, size_t len) {
    g_nvs[key] = std::vector<uint8_t>((const uint8_t *)v, (const uint8_t *)v + len);
    return ESP_OK;
}
esp_err_t nvs_get_u8(nvs_handle_t, const char *key, uint8_t *out) {
    auto it = g_nvs.find(key);
    if (it == g_nvs.end() || it->second.size() != 1) return ESP_FAIL;
    *out = it->second[0];
    return ESP_OK;
}
esp_err_t nvs_set_u8(nvs_handle_t, const char *key, uint8_t val) {
    g_nvs[key] = std::vector<uint8_t>(1, val);
    return ESP_OK;
}
esp_err_t nvs_erase_key(nvs_handle_t, const char *key) {
    return g_nvs.erase(key) ? ESP_OK : ESP_FAIL;
}
esp_err_t nvs_commit(nvs_handle_t) { return ESP_OK; }
void nvs_close(nvs_handle_t) {}
esp_err_t nvs_erase_all(nvs_handle_t) { g_nvs.clear(); return ESP_OK; }

struct MdState {
    std::vector<uint8_t> data;
    std::vector<uint8_t> key;
};
const mbedtls_md_info_t *mbedtls_md_info_from_type(mbedtls_md_type_t t) {
    static mbedtls_md_info_t info = {MBEDTLS_MD_SHA256};
    return t == MBEDTLS_MD_SHA256 ? &info : nullptr;
}
void mbedtls_md_init(mbedtls_md_context_t *c) { c->state = nullptr; c->hmac = 0; }
void mbedtls_md_free(mbedtls_md_context_t *c) { delete (MdState *)c->state; c->state = nullptr; }
int mbedtls_md_setup(mbedtls_md_context_t *c, const mbedtls_md_info_t *, int hmac) {
    delete (MdState *)c->state;
    c->state = new MdState();
    c->hmac = hmac;
    return 0;
}
int mbedtls_md_starts(mbedtls_md_context_t *c) { ((MdState *)c->state)->data.clear(); return 0; }
int mbedtls_md_update(mbedtls_md_context_t *c, const unsigned char *in, size_t n) {
    auto *s = (MdState *)c->state;
    s->data.insert(s->data.end(), in, in + n);
    return 0;
}
int mbedtls_md_finish(mbedtls_md_context_t *c, unsigned char *out) {
    auto *s = (MdState *)c->state;
    unsigned int l = 32;
    EVP_Digest(s->data.data(), s->data.size(), out, &l, EVP_sha256(), nullptr);
    return 0;
}
int mbedtls_md_hmac_starts(mbedtls_md_context_t *c, const unsigned char *key, size_t n) {
    auto *s = (MdState *)c->state;
    s->key.assign(key, key + n);
    s->data.clear();
    return 0;
}
int mbedtls_md_hmac_update(mbedtls_md_context_t *c, const unsigned char *in, size_t n) { return mbedtls_md_update(c, in, n); }
int mbedtls_md_hmac_finish(mbedtls_md_context_t *c, unsigned char *out) {
    auto *s = (MdState *)c->state;
    unsigned int l = 32;
    HMAC(EVP_sha256(), s->key.data(), (int)s->key.size(), s->data.data(), s->data.size(), out, &l);
    return 0;
}

void mbedtls_aes_init(mbedtls_aes_context *c) { memset(c, 0, sizeof(*c)); }
void mbedtls_aes_free(mbedtls_aes_context *c) { memset(c, 0, sizeof(*c)); }
int mbedtls_aes_setkey_enc(mbedtls_aes_context *c, const unsigned char *key, unsigned) { memcpy(c->key, key, 32); c->enc = 1; return 0; }
int mbedtls_aes_setkey_dec(mbedtls_aes_context *c, const unsigned char *key, unsigned) { memcpy(c->key, key, 32); c->enc = 0; return 0; }
int mbedtls_aes_crypt_cbc(mbedtls_aes_context *c, int mode, size_t len, unsigned char iv[16], const unsigned char *in, unsigned char *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), nullptr, c->key, iv, mode == MBEDTLS_AES_ENCRYPT);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int outl = 0, fin = 0;
    EVP_CipherUpdate(ctx, out, &outl, in, (int)len);
    EVP_CipherFinal_ex(ctx, out + outl, &fin);
    EVP_CIPHER_CTX_free(ctx);
    if (len >= 16) {
        if (mode == MBEDTLS_AES_ENCRYPT) memcpy(iv, out + len - 16, 16);
        else memcpy(iv, in + len - 16, 16);
    }
    return 0;
}
int mbedtls_pkcs5_pbkdf2_hmac_ext(mbedtls_md_type_t, const unsigned char *pw, size_t plen, const unsigned char *salt, size_t slen, unsigned int iters, uint32_t keylen, unsigned char *out) {
    return PKCS5_PBKDF2_HMAC((const char *)pw, (int)plen, salt, (int)slen, (int)iters, EVP_sha256(), (int)keylen, out) ? 0 : -1;
}

size_t fromHex(const String &hex, byte *output, size_t max_len) {
    size_t len = hex.length() / 2;
    if (len > max_len) len = max_len;
    memset(output, 0, max_len);
    for (size_t i = 0; i < len; i++) {
        String byteString = hex.substring(i * 2, i * 2 + 2);
        output[i] = (byte)strtol(byteString.c_str(), NULL, 16);
    }
    return len;
}
String toHex(const byte *data, size_t len) {
    String out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        char buf[3];
        snprintf(buf, sizeof buf, "%02x", data[i]);
        out += buf;
    }
    return out;
}
String hashSHA256(const String &input) {
    uint8_t out[32];
    unsigned int l = 32;
    EVP_Digest(input.c_str(), input.length(), out, &l, EVP_sha256(), nullptr);
    return toHex(out, 32);
}
static int g_fidoSource = FIDO_KEY_SRC_NVS_SECRET;
static bool g_fidoSourceBroken[3] = {false, false, false};
void host_set_fido_source(int s) { g_fidoSource = s; }
void host_break_fido_source(int s, bool broken) { g_fidoSourceBroken[s] = broken; }
int currentFidoKeySource() { return g_fidoSource; }
bool getFidoKeyForSource(int source, byte *outKey256) {
    if (source < 0 || source > 2 || g_fidoSourceBroken[source]) return false;
    memset(outKey256, 0x40 + source, 32);
    return true;
}
void getFidoHardwareKey(byte *outKey256) { getFidoKeyForSource(g_fidoSource, outKey256); }

String encryptStoragePayload(const String &plainText, const byte *key256) {
    uint8_t iv[12];
    RAND_bytes(iv, 12);
    size_t len = plainText.length();
    std::vector<uint8_t> cipher(len + 16);
    uint8_t tag[16];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key256, iv);
    int outl = 0, fin = 0;
    EVP_EncryptUpdate(ctx, cipher.data(), &outl, (const uint8_t *)plainText.c_str(), (int)len);
    EVP_EncryptFinal_ex(ctx, cipher.data() + outl, &fin);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    return toHex(iv, 12) + ":" + toHex(cipher.data(), len) + ":" + toHex(tag, 16);
}
String decryptStoragePayload(const String &payload, const byte *key256) {
    int c1 = payload.indexOf(':');
    int c2 = payload.indexOf(':', c1 + 1);
    if (c1 == -1 || c2 == -1) return "";
    String ivHex = payload.substring(0, c1);
    String cipherHex = payload.substring(c1 + 1, c2);
    String tagHex = payload.substring(c2 + 1);
    if (ivHex.length() != 24 || tagHex.length() != 32) return "";
    size_t cl = cipherHex.length() / 2;
    if (cl == 0) return "";
    uint8_t iv[12], tag[16];
    fromHex(ivHex, iv, 12);
    fromHex(tagHex, tag, 16);
    std::vector<uint8_t> cipher(cl), plain(cl + 16);
    fromHex(cipherHex, cipher.data(), cl);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key256, iv);
    int outl = 0, fin = 0;
    EVP_DecryptUpdate(ctx, plain.data(), &outl, cipher.data(), (int)cl);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    int ok = EVP_DecryptFinal_ex(ctx, plain.data() + outl, &fin);
    EVP_CIPHER_CTX_free(ctx);
    if (ok <= 0) return "";
    String r;
    r.s.assign((const char *)plain.data(), cl);
    return r;
}

void CommsManager::sendEvent(const String &module, const String &event, JsonDocument *data) {
    std::string line = "event:" + module.s + ":" + event.s;
    if (data && !data->isNull()) {
        String out;
        serializeJson(*data, out);
        line += ":" + out.s;
    }
    g_events.push_back(line);
}
void CommsManager::sendError(const String &module, const String &errCode, const String &) {
    g_events.push_back("error:" + module.s + ":" + errCode.s);
}

void deleteAllFingerprints() {}
String generateTOTP(const String &secret, uint32_t t) { return "000000"; }
