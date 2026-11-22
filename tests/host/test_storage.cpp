#include "Arduino.h"
#include "SPIFFS.h"
#include "nvs.h"
#include "Globals.h"
#include "StorageManager.h"
#include "CryptoManager.h"
#include "CommsManager.h"
#include "host_hooks.h"
#include "mbedtls/md.h"
#include "mbedtls/aes.h"
#include <openssl/evp.h>
#include <random>
#include <set>
#include <functional>

static int g_fail = 0, g_pass = 0;
#define EXPECT(c) do { if (!(c)) { g_fail++; printf("    FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } else g_pass++; } while (0)
#define RUN(fn) do { host_reset_environment(); storageMutex = (SemaphoreHandle_t)1; int before = g_fail; fn(); int lv = host_lock_violations(); if (lv) { g_fail++; printf("    FAIL lock discipline: %d violation(s)\n", lv); } printf("[%s] %s\n", g_fail == before ? "PASS" : "FAIL", #fn); } while (0)

typedef std::vector<uint8_t> Bytes;

static bool wrapCred(const String &rp, const uint8_t *uid, size_t uidLen, const String &name, const String &privHex, int alg, uint8_t *out, size_t cap, size_t &len) {
#ifdef LEGACY_STORAGE
    (void)cap;
    return wrapStatelessCredential(rp, uid, uidLen, name, privHex, alg, out, len);
#else
    return wrapStatelessCredential(rp, uid, uidLen, name, privHex, alg, out, cap, len);
#endif
}

static Bytes &fsFile(const char *p) { return host_fs()[p]; }
static bool fsHas(const char *p) { return host_fs().count(p) > 0; }
static void put16(Bytes &v, uint16_t x) { v.push_back(x & 0xFF); v.push_back(x >> 8); }
static Bytes frame(uint8_t status, int alg, const std::string &cid, const std::string &rp, const std::string &pay) {
    Bytes v;
    v.push_back(status);
    for (int i = 0; i < 4; i++) v.push_back(((uint32_t)alg >> (8 * i)) & 0xFF);
    put16(v, (uint16_t)cid.size()); v.insert(v.end(), cid.begin(), cid.end());
    put16(v, (uint16_t)rp.size()); v.insert(v.end(), rp.begin(), rp.end());
    put16(v, (uint16_t)pay.size()); v.insert(v.end(), pay.begin(), pay.end());
    return v;
}
static byte *fidoKey() { static byte k[32]; getFidoHardwareKey(k); return k; }
static std::string encPayload(const std::string &plain) { return encryptStoragePayload(String(plain.c_str()), fidoKey()).s; }
static std::string hexOf(const Bytes &b) { return toHex(b.data(), b.size()).s; }
static std::string hexRepeat(const char *two, int n) { std::string r; for (int i = 0; i < n; i++) r += two; return r; }

static bool savePk(const char *cid, const char *rp, const char *uid, const std::string &name, const char *priv, int alg = -7, int cp = 1, const char *lbk = "", const char *blob = "") {
    return savePasskeyRecord(cid, rp, uid, String(name.c_str()), priv, alg, cp, lbk, blob);
}
struct Pk { bool ok; String rp, uid, name, priv, lbk, blob; int alg = 0, cp = 0; };
static Pk getPk(const char *cid) {
    Pk r;
    r.ok = getPasskeyRecord(cid, r.rp, r.uid, r.name, r.priv, r.alg, r.cp, r.lbk, r.blob);
    return r;
}
static void touchAllReaders(const char *cid, const char *rp) {
    getPk(cid);
    isPasskeyExists(cid);
    findAllCredentialsByRp(rp);
    getAllStoredCredentialIds();
    getAllStoredRpIds();
    findCredentialIdByRpAndUser(rp, "");
    getFidoWebsiteInfo(rp);
    listFidoWebsites();
}

static void test_passkey_roundtrip() {
    std::string lbk = hexRepeat("bb", 32), blob = hexRepeat("cc", 16), priv = hexRepeat("11", 32);
    EXPECT(savePk("aa11", "example.com", "0102", "alice", priv.c_str(), -49, 2, lbk.c_str(), blob.c_str()));
    Pk r = getPk("aa11");
    EXPECT(r.ok);
    EXPECT(r.rp == "example.com" && r.uid == "0102" && r.name == "alice" && r.priv == priv.c_str());
    EXPECT(r.alg == -49 && r.cp == 2 && r.lbk == lbk.c_str() && r.blob == blob.c_str());
    String rp, uid, name, privOut; int alg = 0;
    EXPECT(getPasskeyRecord("aa11", rp, uid, name, privOut, alg));
    EXPECT(alg == -49 && name == "alice");
    EXPECT(!getPk("zz99").ok);
    bool saved = false;
    for (auto &e : host_events()) if (e == "event:FIDO2:PASSKEY_SAVED") saved = true;
    EXPECT(saved);
}

static void test_passkey_username_special_chars() {
    std::vector<std::string> names = {
        "", "alice", "a\nb", "a\r\nb\n\n", "\n", "\n\n\n", "x\ny\nz\nw\nv\nu",
        "x\nDEADBEEF\n3\nAA\nBB", "V2", "V2\nfoo", "name with spaces", "日本語ユーザー",
        std::string(64, 'A'), "tab\there", "quote\"s'and\\backslash", ":::", "0102"};
    std::string priv = hexRepeat("22", 32);
    for (auto &n : names) {
        host_fs().clear();
        EXPECT(savePk("c1", "rp.example", "0a0b", n, priv.c_str(), -7, 3, "aabb", "ccdd"));
        Pk r = getPk("c1");
        EXPECT(r.ok);
        if (!(r.name == n.c_str())) printf("    name mismatch for %zu-byte name: got '%s'\n", n.size(), r.name.c_str());
        EXPECT(r.name == n.c_str());
        EXPECT(r.uid == "0a0b");
        EXPECT(r.priv == priv.c_str());
        EXPECT(r.cp == 3);
        EXPECT(r.lbk == "aabb");
        EXPECT(r.blob == "ccdd");
        EXPECT(findCredentialIdByRpAndUser("rp.example", "0a0b") == "c1");
    }
}

static void test_passkey_legacy_payloads_still_readable() {
    struct L { std::string payload; const char *uid, *name, *priv; int cp; const char *lbk, *blob; };
    std::vector<L> cases = {
        {"0102\nbob\nPRIV", "0102", "bob", "PRIV", 1, "", ""},
        {"0102\nbob\nPRIV\n3", "0102", "bob", "PRIV", 3, "", ""},
        {"0102\nbob\nPRIV\n2\nLBK", "0102", "bob", "PRIV", 2, "LBK", ""},
        {"0102\nbob\nPRIV\n2\nLBK\nBLOB", "0102", "bob", "PRIV", 2, "LBK", "BLOB"},
        {"0102\nbob\nPRIV\n\nLBK\nBLOB", "0102", "bob", "PRIV", 1, "LBK", "BLOB"},
        {"\n\nPRIV", "", "", "PRIV", 1, "", ""},
    };
    int i = 0;
    for (auto &c : cases) {
        host_fs().clear();
        std::string cid = "legacy" + std::to_string(i++);
        Bytes f = frame(1, -7, cid, "old.example", encPayload(c.payload));
        fsFile("/passkeys.bin") = f;
        Pk r = getPk(cid.c_str());
        EXPECT(r.ok);
        EXPECT(r.uid == c.uid && r.name == c.name && r.priv == c.priv);
        EXPECT(r.cp == c.cp && r.lbk == c.lbk && r.blob == c.blob);
        EXPECT(r.rp == "old.example" && r.alg == -7);
        if (std::string(c.uid).size()) EXPECT(findCredentialIdByRpAndUser("old.example", c.uid) == cid.c_str());
        String info = getFidoWebsiteInfo("old.example");
        EXPECT(info == (String(c.name) + " | CRED_ID:" + cid.c_str() + "\n"));
    }
    host_fs().clear();
    fsFile("/passkeys.bin") = frame(1, -7, "nonl", "old.example", encPayload("justonefield"));
    EXPECT(!getPk("nonl").ok);
    fsFile("/passkeys.bin") = frame(1, -7, "twof", "old.example", encPayload("a\nb"));
    EXPECT(!getPk("twof").ok);
}

static void test_passkey_record_layout() {
    std::string priv = hexRepeat("33", 32);
    EXPECT(savePk("deadbeef", "layout.example", "ff00", "carol", priv.c_str(), -49));
    Bytes &f = fsFile("/passkeys.bin");
    EXPECT(f.size() > 11);
    size_t o = 0;
    EXPECT(f[o++] == 1);
    EXPECT(f[1] == 0xCF && f[2] == 0xFF && f[3] == 0xFF && f[4] == 0xFF);
    o = 5;
    auto readField = [&](std::string &out) {
        if (o + 2 > f.size()) return false;
        size_t n = f[o] | (f[o + 1] << 8);
        o += 2;
        if (o + n > f.size()) return false;
        out.assign((const char *)&f[o], n);
        o += n;
        return true;
    };
    std::string cid, rp, pay;
    EXPECT(readField(cid) && readField(rp) && readField(pay));
    EXPECT(cid == "deadbeef" && rp == "layout.example");
    EXPECT(o == f.size());
    String plain = decryptStoragePayload(String(pay.c_str()), fidoKey());
    EXPECT(plain.length() > 0);
    EXPECT(plain.indexOf("ff00") >= 0);
    EXPECT(plain.indexOf(String(priv.c_str())) >= 0);
    EXPECT(pay.find(':') != std::string::npos);
    EXPECT(pay.size() <= 0xFFFF);
}

static void test_passkey_multi_record_operations() {
    std::string p = hexRepeat("44", 32);
    EXPECT(savePk("c1", "a.com", "u1", "one", p.c_str()));
    EXPECT(savePk("c2", "a.com", "u2", "two", p.c_str()));
    EXPECT(savePk("c3", "b.com", "u3", "three", p.c_str()));
    EXPECT(isPasskeyExists("c1") && isPasskeyExists("c2") && isPasskeyExists("c3") && !isPasskeyExists("c4"));
    auto a = findAllCredentialsByRp("a.com");
    EXPECT(a.size() == 2 && a[0] == "c1" && a[1] == "c2");
    EXPECT(findAllCredentialsByRp("b.com").size() == 1);
    EXPECT(findAllCredentialsByRp("nope.com").empty());
    EXPECT(getAllStoredCredentialIds().size() == 3);
    auto rps = getAllStoredRpIds();
    std::set<std::string> rpset;
    for (auto &r : rps) rpset.insert(r.s);
    EXPECT(rpset.count("a.com") && rpset.count("b.com"));
    EXPECT(findCredentialIdByRpAndUser("a.com", "u2") == "c2");
    EXPECT(findCredentialIdByRpAndUser("a.com", "") == "c1");
    EXPECT(findCredentialIdByRpAndUser("a.com", "u9") == "");
    uint8_t bin[8] = {0};
    host_fs().clear();
    EXPECT(savePk("0a0b0c0d", "a.com", "u1", "one", p.c_str()));
    EXPECT(getBinaryCredentialId("a.com", "u1", bin, sizeof bin) == 4 && bin[0] == 0x0a && bin[3] == 0x0d);
    EXPECT(getBinaryCredentialId("a.com", "u1", bin, 2) == 0);
    host_fs().clear();
    savePk("c1", "a.com", "u1", "one", p.c_str());
    savePk("c2", "a.com", "u2", "two", p.c_str());
    savePk("c3", "b.com", "u3", "three", p.c_str());
    size_t before = fsFile("/passkeys.bin").size();
    EXPECT(deletePasskeyRecord("c2"));
    EXPECT(fsFile("/passkeys.bin").size() < before);
    EXPECT(!isPasskeyExists("c2") && getPk("c1").ok && getPk("c3").ok);
    EXPECT(getPk("c1").name == "one" && getPk("c3").name == "three");
    EXPECT(!deletePasskeyRecord("c2"));
    EXPECT(!fsHas("/passkeys.tmp"));
    EXPECT(deleteFidoWebsite("a.com"));
    EXPECT(!isPasskeyExists("c1") && getPk("c3").ok);
    EXPECT(!deleteFidoWebsite("a.com"));
    EXPECT(!fsHas("/passkeys.tmp"));
    host_events().clear();
    listFidoWebsites();
    bool listed = false;
    for (auto &e : host_events()) if (e.find("event:FIDO2:LIST") == 0 && e.find("b.com") != std::string::npos && e.find("\"discoverable_credentials_used\":1") != std::string::npos) listed = true;
    EXPECT(listed);
}

static void test_passkey_website_info_listing() {
    std::string p = hexRepeat("55", 32);
    savePk("cc01", "info.example", "u1", "Alice A", p.c_str());
    savePk("cc02", "info.example", "u2", "Bob\nB", p.c_str());
    savePk("cc03", "other.example", "u3", "Eve", p.c_str());
    clearStorageKey();
    String info = getFidoWebsiteInfo("info.example");
    EXPECT(info.indexOf("Alice A | CRED_ID:cc01") >= 0);
    EXPECT(info.indexOf("Bob\nB | CRED_ID:cc02") >= 0);
    EXPECT(info.indexOf("Eve") < 0);
}

static void test_passkey_truncation_sweep() {
    std::string p = hexRepeat("66", 32);
    savePk("cid-one", "one.example", "01", "first", p.c_str(), -7, 2, "aa", "bb");
    size_t size1 = fsFile("/passkeys.bin").size();
    savePk("cid-two", "two.example", "02", "second\nuser", p.c_str(), -8, 3, "cc", "dd");
    Bytes original = fsFile("/passkeys.bin");
    size_t total = original.size();
    std::set<std::string> valid = {"cid-one", "cid-two"};
    std::set<std::string> validRp = {"one.example", "two.example"};
    for (size_t L = 0; L <= total; L++) {
        fsFile("/passkeys.bin") = Bytes(original.begin(), original.begin() + L);
        Pk r1 = getPk("cid-one"), r2 = getPk("cid-two");
        if (r1.ok != (L >= size1) || r2.ok != (L == total)) printf("    sweep mismatch at L=%zu (size1=%zu total=%zu) r1=%d r2=%d\n", L, size1, total, r1.ok, r2.ok);
        EXPECT(r1.ok == (L >= size1));
        EXPECT(r2.ok == (L == total));
        if (r1.ok) EXPECT(r1.name == "first" && r1.priv == p.c_str() && r1.cp == 2 && r1.lbk == "aa" && r1.blob == "bb");
        if (r2.ok) EXPECT(r2.name == "second\nuser" && r2.priv == p.c_str() && r2.cp == 3 && r2.alg == -8);
        EXPECT(isPasskeyExists("cid-two") == (L == total));
        for (auto &id : getAllStoredCredentialIds()) EXPECT(valid.count(id.s) == 1);
        for (auto &rp : getAllStoredRpIds()) EXPECT(validRp.count(rp.s) == 1);
        for (auto &id : findAllCredentialsByRp("two.example")) EXPECT(valid.count(id.s) == 1);
        listFidoWebsites();
        getFidoWebsiteInfo("one.example");
        findCredentialIdByRpAndUser("two.example", "02");
        deletePasskeyRecord("cid-one");
        for (auto &id : getAllStoredCredentialIds()) EXPECT(valid.count(id.s) == 1);
        EXPECT(!fsHas("/passkeys.tmp"));
        fsFile("/passkeys.bin") = Bytes(original.begin(), original.begin() + L);
        deleteFidoWebsite("one.example");
        for (auto &id : getAllStoredCredentialIds()) EXPECT(valid.count(id.s) == 1);
        EXPECT(!fsHas("/passkeys.tmp"));
    }
}

static void test_passkey_corrupt_length_fields() {
    std::string p = hexRepeat("77", 32);
    savePk("cid-a", "a.example", "01", "n", p.c_str());
    Bytes original = fsFile("/passkeys.bin");
    size_t cidLenPos = 5;
    size_t rpLenPos = 5 + 2 + 5;
    size_t payLenPos = rpLenPos + 2 + 9;
    for (size_t pos : {cidLenPos, rpLenPos, payLenPos}) {
        for (uint16_t v : {0, 1, 2, 0x00FF, 0x0100, 0x7FFF, 0xFFFE, 0xFFFF}) {
            Bytes f = original;
            f[pos] = v & 0xFF;
            f[pos + 1] = v >> 8;
            fsFile("/passkeys.bin") = f;
            touchAllReaders("cid-a", "a.example");
            deletePasskeyRecord("cid-a");
            fsFile("/passkeys.bin") = f;
            deleteFidoWebsite("a.example");
            fsFile("/passkeys.bin") = f;
            Pk r = getPk("cid-a");
            if (v != (f == original ? v : 0) && r.ok) EXPECT(r.name == "n");
        }
    }
    for (int status = 0; status < 256; status++) {
        Bytes f = original;
        f[0] = (uint8_t)status;
        fsFile("/passkeys.bin") = f;
        Pk r = getPk("cid-a");
        EXPECT(r.ok == (status == 1));
        EXPECT(isPasskeyExists("cid-a") == (status == 1));
    }
}

static void test_passkey_random_corruption_is_safe() {
    std::string p = hexRepeat("88", 32);
    savePk("cid-a", "a.example", "01", "alpha", p.c_str(), -7, 2, "aa", "bb");
    savePk("cid-b", "b.example", "02", "beta\ngamma", p.c_str(), -8, 3, "cc", "dd");
    savePk("cid-c", "a.example", "03", "", p.c_str(), -257, 1, "", "");
    Bytes original = fsFile("/passkeys.bin");
    std::mt19937 rng(7);
    for (int i = 0; i < 4000; i++) {
        Bytes f = original;
        int muts = 1 + rng() % 4;
        for (int m = 0; m < muts; m++) {
            switch (rng() % 4) {
                case 0: f[rng() % f.size()] ^= 1 << (rng() % 8); break;
                case 1: f[rng() % f.size()] = rng(); break;
                case 2: f.resize(rng() % (f.size() + 1)); if (f.empty()) f.push_back(0); break;
                case 3: f.insert(f.begin() + rng() % f.size(), (uint8_t)rng()); break;
            }
        }
        fsFile("/passkeys.bin") = f;
        touchAllReaders("cid-b", "a.example");
        deletePasskeyRecord("cid-a");
        fsFile("/passkeys.bin") = f;
        deleteFidoWebsite("b.example");
        EXPECT(!fsHas("/passkeys.tmp"));
    }
}

static void test_passkey_oversized_fields_rejected() {
    std::string p = hexRepeat("99", 32);
    savePk("good", "good.example", "01", "ok", p.c_str());
    Bytes before = fsFile("/passkeys.bin");
    EXPECT(!savePk("bad1", std::string(70000, 'a').c_str(), "01", "n", p.c_str()));
    EXPECT(fsFile("/passkeys.bin") == before);
    EXPECT(!savePk(std::string(70000, 'b').c_str(), "x.example", "01", "n", p.c_str()));
    EXPECT(fsFile("/passkeys.bin") == before);
    EXPECT(!savePk("", "x.example", "01", "n", p.c_str()));
    EXPECT(fsFile("/passkeys.bin") == before);
    EXPECT(getPk("good").ok);
    EXPECT(getAllStoredCredentialIds().size() == 1);
}

static void sha256Raw(const Bytes &in, uint8_t out[32]) {
    unsigned int l = 32;
    EVP_Digest(in.data(), in.size(), out, &l, EVP_sha256(), nullptr);
}
static void statelessKeys(uint8_t aes[32], uint8_t hm[32]) {
    if (!host_nvs().count("sl_secret")) {
        uint8_t secret[32];
        for (int i = 0; i < 32; i++) secret[i] = (uint8_t)(i * 7 + 1);
        nvs_set_blob(0, "sl_secret", secret, 32);
    }
    Bytes sec = host_nvs()["sl_secret"];
    Bytes a = sec, h = sec;
    const char *sa = "STATELESS_AES_KEY_SALT", *sh = "STATELESS_HMAC_KEY_SALT";
    a.insert(a.end(), sa, sa + strlen(sa));
    h.insert(h.end(), sh, sh + strlen(sh));
    sha256Raw(a, aes);
    sha256Raw(h, hm);
}
static Bytes sealBlob(Bytes plain) {
    while (plain.size() % 16 != 0) plain.push_back(0);
    uint8_t aes[32], hm[32];
    statelessKeys(aes, hm);
    uint8_t iv[16], ivc[16];
    for (int i = 0; i < 16; i++) iv[i] = (uint8_t)(0xA0 + i);
    memcpy(ivc, iv, 16);
    Bytes enc(plain.size());
    mbedtls_aes_context c;
    mbedtls_aes_init(&c);
    mbedtls_aes_setkey_enc(&c, aes, 256);
    mbedtls_aes_crypt_cbc(&c, MBEDTLS_AES_ENCRYPT, plain.size(), ivc, plain.data(), enc.data());
    mbedtls_md_context_t m;
    mbedtls_md_init(&m);
    mbedtls_md_setup(&m, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&m, hm, 32);
    mbedtls_md_hmac_update(&m, iv, 16);
    mbedtls_md_hmac_update(&m, enc.data(), enc.size());
    uint8_t mac[32];
    mbedtls_md_hmac_finish(&m, mac);
    mbedtls_md_free(&m);
    Bytes out(iv, iv + 16);
    out.insert(out.end(), enc.begin(), enc.end());
    out.insert(out.end(), mac, mac + 32);
    return out;
}
static Bytes openBlob(const Bytes &blob) {
    uint8_t aes[32], hm[32];
    statelessKeys(aes, hm);
    size_t encLen = blob.size() - 48;
    uint8_t iv[16];
    memcpy(iv, blob.data(), 16);
    Bytes plain(encLen);
    mbedtls_aes_context c;
    mbedtls_aes_init(&c);
    mbedtls_aes_setkey_dec(&c, aes, 256);
    mbedtls_aes_crypt_cbc(&c, MBEDTLS_AES_DECRYPT, encLen, iv, blob.data() + 16, plain.data());
    return plain;
}
static Bytes rpHash(const std::string &rp) {
    Bytes in(rp.begin(), rp.end()), out(32);
    sha256Raw(in, out.data());
    return out;
}
static Bytes v1Plain(const std::string &rp, int alg, const Bytes &uid, uint8_t uidLenField, const std::string &name, uint8_t nameLenField, const Bytes &priv, uint16_t privLenField) {
    Bytes p(108 + priv.size(), 0);
    memcpy(&p[0], "STAT", 4);
    for (int i = 0; i < 4; i++) p[4 + i] = ((uint32_t)alg >> (24 - 8 * i)) & 0xFF;
    Bytes h = rpHash(rp);
    memcpy(&p[8], h.data(), 32);
    p[40] = uidLenField;
    if (!uid.empty()) memcpy(&p[41], uid.data(), uid.size() > 32 ? 32 : uid.size());
    p[73] = nameLenField;
    if (!name.empty()) memcpy(&p[74], name.data(), name.size() > 32 ? 32 : name.size());
    p[106] = privLenField >> 8;
    p[107] = privLenField & 0xFF;
    if (!priv.empty()) memcpy(&p[108], priv.data(), priv.size());
    return p;
}
static Bytes v2Plain(const char *magic, const std::string &rp, int alg, uint8_t uidLenField, const Bytes &uid, uint8_t nameLenField, const std::string &name, uint16_t privLenField, const Bytes &priv) {
    Bytes p;
    p.insert(p.end(), magic, magic + 4);
    for (int i = 0; i < 4; i++) p.push_back(((uint32_t)alg >> (24 - 8 * i)) & 0xFF);
    Bytes h = rpHash(rp);
    p.insert(p.end(), h.begin(), h.end());
    p.push_back(uidLenField);
    p.insert(p.end(), uid.begin(), uid.end());
    p.push_back(nameLenField);
    p.insert(p.end(), name.begin(), name.end());
    p.push_back(privLenField >> 8);
    p.push_back(privLenField & 0xFF);
    p.insert(p.end(), priv.begin(), priv.end());
    return p;
}
static bool unwrapBlob(const Bytes &b, const std::string &rp, String &uid, String &name, String &priv, int &alg) {
    return unwrapStatelessCredential(b.data(), b.size(), String(rp.c_str()), uid, name, priv, alg);
}
static Bytes seqBytes(size_t n, uint8_t start = 1) { Bytes b(n); for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(start + i); return b; }

static void test_stateless_roundtrip_matrix() {
    std::string priv = hexRepeat("5a", 32);
    for (size_t uidLen : {0, 1, 16, 32, 33, 48, 63, 64}) {
        for (const char *nm : {"", "alice", "日本語"}) {
            for (int alg : {-7, -8}) {
                Bytes uid = seqBytes(uidLen, 0x10);
                uint8_t out[300];
                size_t len = 0;
                bool ok = wrapCred("stateless.example", uid.data(), uidLen, nm, priv.c_str(), alg, out, sizeof out, len);
                if (!ok) printf("    wrap failed: uidLen=%zu name='%s'\n", uidLen, nm);
                EXPECT(ok);
                if (!ok) continue;
                EXPECT(len >= 96 && len <= 224 && (len - 48) % 16 == 0);
                String uo, no, po; int ao = 0;
                bool un = unwrapStatelessCredential(out, len, "stateless.example", uo, no, po, ao);
                EXPECT(un);
                if (!un) continue;
                if (!(uo == toHex(uid.data(), uidLen))) printf("    user id mismatch for uidLen=%zu (got %u hex chars)\n", uidLen, uo.length());
                EXPECT(uo == toHex(uid.data(), uidLen));
                EXPECT(no == nm);
                EXPECT(po == priv.c_str());
                EXPECT(ao == alg);
            }
        }
    }
}

static void test_stateless_rejects_bad_inputs() {
    std::string priv = hexRepeat("5b", 32);
    Bytes uid = seqBytes(16);
    uint8_t out[300];
    size_t len = 77;
    EXPECT(!wrapCred("rp", uid.data(), 65, "n", priv.c_str(), -7, out, sizeof out, len));
    EXPECT(!wrapCred("rp", uid.data(), 16, "n", (priv + "0").c_str(), -7, out, sizeof out, len));
    EXPECT(!wrapCred("rp", uid.data(), 16, "n", "zz", -7, out, sizeof out, len));
    EXPECT(!wrapCred("rp", uid.data(), 16, "n", "", -7, out, sizeof out, len));
    EXPECT(!wrapCred("rp", nullptr, 16, "n", priv.c_str(), -7, out, sizeof out, len));
    memset(out, 0xAA, sizeof out);
    EXPECT(!wrapCred("rp", uid.data(), 16, "n", priv.c_str(), -7, out, 100, len));
    bool canary = true;
    for (size_t i = 100; i < sizeof out; i++) if (out[i] != 0xAA) canary = false;
    EXPECT(canary);
    memset(out, 0xAA, sizeof out);
    std::string bigPriv = hexRepeat("5c", 200);
    EXPECT(!wrapCred("rp", uid.data(), 16, "n", bigPriv.c_str(), -7, out, 224, len));
    canary = true;
    for (size_t i = 224; i < sizeof out; i++) if (out[i] != 0xAA) canary = false;
    EXPECT(canary);
}

static void test_stateless_tamper_and_truncation() {
    std::string priv = hexRepeat("5d", 32);
    Bytes uid = seqBytes(16);
    uint8_t out[300];
    size_t len = 0;
    EXPECT(wrapCred("tamper.example", uid.data(), 16, "alice", priv.c_str(), -7, out, sizeof out, len));
    Bytes good(out, out + len);
    String u, n, p; int a;
    EXPECT(unwrapBlob(good, "tamper.example", u, n, p, a));
    EXPECT(!unwrapBlob(good, "other.example", u, n, p, a));
    EXPECT(!unwrapBlob(good, "", u, n, p, a));
    for (size_t i = 0; i < good.size(); i++) {
        for (int bit = 0; bit < 8; bit++) {
            Bytes b = good;
            b[i] ^= 1 << bit;
            if (unwrapBlob(b, "tamper.example", u, n, p, a)) { printf("    tampered byte %zu bit %d accepted\n", i, bit); EXPECT(false); }
        }
    }
    for (size_t L = 0; L < good.size(); L++) {
        Bytes b(good.begin(), good.begin() + L);
        if (unwrapBlob(b, "tamper.example", u, n, p, a)) { printf("    truncated to %zu accepted\n", L); EXPECT(false); }
    }
    for (size_t extra = 1; extra <= 33; extra++) {
        Bytes b = good;
        b.insert(b.end() - 32, extra, 0);
        EXPECT(!unwrapBlob(b, "tamper.example", u, n, p, a));
        Bytes c = good;
        c.insert(c.end(), extra, 0);
        EXPECT(!unwrapBlob(c, "tamper.example", u, n, p, a));
    }
    EXPECT(!unwrapStatelessCredential(nullptr, 0, "x", u, n, p, a));
    EXPECT(!unwrapStatelessCredential(good.data(), 0, "x", u, n, p, a));
}

static void test_stateless_legacy_v1_compatibility() {
    String u, n, p; int a;
    Bytes priv32 = seqBytes(32, 0x40);
    {
        Bytes plain = v1Plain("v1.example", -7, seqBytes(32, 1), 32, std::string(32, 'N'), 32, priv32, 32);
        Bytes blob = sealBlob(plain);
        EXPECT(unwrapBlob(blob, "v1.example", u, n, p, a));
        EXPECT(u == toHex(seqBytes(32, 1).data(), 32) && n == std::string(32, 'N').c_str() && p == toHex(priv32.data(), 32) && a == -7);
    }
    {
        Bytes plain = v1Plain("v1.example", -8, Bytes(), 0, "", 0, priv32, 32);
        Bytes blob = sealBlob(plain);
        EXPECT(unwrapBlob(blob, "v1.example", u, n, p, a));
        EXPECT(u == "" && n == "" && p == toHex(priv32.data(), 32) && a == -8);
    }
    {
        Bytes plain = v1Plain("v1.example", -7, seqBytes(8), 8, "bob", 3, priv32, 32);
        EXPECT(unwrapBlob(sealBlob(plain), "v1.example", u, n, p, a));
        EXPECT(u == toHex(seqBytes(8).data(), 8) && n == "bob");
        EXPECT(!unwrapBlob(sealBlob(plain), "different.example", u, n, p, a));
    }
    {
        Bytes plain = v1Plain("v1.example", -7, seqBytes(8), 8, "bob", 3, priv32, 5000);
        EXPECT(!unwrapBlob(sealBlob(plain), "v1.example", u, n, p, a));
    }
    {
        Bytes plain = v1Plain("v1.example", -7, seqBytes(8), 8, "bob", 3, priv32, 37);
        EXPECT(!unwrapBlob(sealBlob(plain), "v1.example", u, n, p, a));
    }
    {
        Bytes shortPlain(80, 0);
        memcpy(shortPlain.data(), "STAT", 4);
        Bytes h = rpHash("v1.example");
        memcpy(&shortPlain[8], h.data(), 32);
        EXPECT(!unwrapBlob(sealBlob(shortPlain), "v1.example", u, n, p, a));
    }
}

static void test_stateless_forged_authentic_blobs() {
    String u, n, p; int a;
    Bytes priv = seqBytes(32, 0x30);
    {
        Bytes ok = v2Plain("STA2", "forge.example", -7, 4, seqBytes(4), 3, "bob", 32, priv);
        EXPECT(unwrapBlob(sealBlob(ok), "forge.example", u, n, p, a));
        EXPECT(u == "01020304" && n == "bob" && p == toHex(priv.data(), 32) && a == -7);
    }
    {
        Bytes ok = v2Plain("STA2", "forge.example", -49, 0, Bytes(), 0, "", 1, Bytes(1, 0xEE));
        EXPECT(unwrapBlob(sealBlob(ok), "forge.example", u, n, p, a));
        EXPECT(u == "" && n == "" && p == "ee" && a == -49);
    }
    EXPECT(!unwrapBlob(sealBlob(v2Plain("STA3", "forge.example", -7, 4, seqBytes(4), 3, "bob", 32, priv)), "forge.example", u, n, p, a));
    EXPECT(!unwrapBlob(sealBlob(v2Plain("STA2", "forge.example", -7, 65, seqBytes(65), 3, "bob", 32, priv)), "forge.example", u, n, p, a));
    EXPECT(!unwrapBlob(sealBlob(v2Plain("STA2", "forge.example", -7, 200, seqBytes(8), 3, "bob", 32, priv)), "forge.example", u, n, p, a));
    EXPECT(!unwrapBlob(sealBlob(v2Plain("STA2", "forge.example", -7, 4, seqBytes(4), 33, std::string(33, 'x'), 32, priv)), "forge.example", u, n, p, a));
    EXPECT(!unwrapBlob(sealBlob(v2Plain("STA2", "forge.example", -7, 4, seqBytes(4), 3, "bob", 0xFFFF, priv)), "forge.example", u, n, p, a));
    EXPECT(!unwrapBlob(sealBlob(v2Plain("STA2", "forge.example", -7, 4, seqBytes(4), 3, "bob", 60, priv)), "forge.example", u, n, p, a));
    EXPECT(!unwrapBlob(sealBlob(v2Plain("STA2", "forge.example", -7, 4, seqBytes(4), 3, "bob", 0, Bytes())), "forge.example", u, n, p, a));
    Bytes truncated = v2Plain("STA2", "forge.example", -7, 4, seqBytes(4), 3, "bob", 32, priv);
    for (size_t L = 0; L < truncated.size(); L++) {
        Bytes cut(truncated.begin(), truncated.begin() + L);
        while (cut.size() < 48) cut.push_back(0);
        unwrapBlob(sealBlob(cut), "forge.example", u, n, p, a);
    }
    for (size_t sz : {48, 64, 80, 96, 112, 128}) {
        Bytes junk(sz, 0);
        memcpy(junk.data(), "STA2", 4);
        Bytes h = rpHash("forge.example");
        memcpy(&junk[8], h.data(), 32);
        for (size_t i = 40; i < sz; i++) junk[i] = (uint8_t)(i * 31);
        unwrapBlob(sealBlob(junk), "forge.example", u, n, p, a);
        memcpy(junk.data(), "STAT", 4);
        unwrapBlob(sealBlob(junk), "forge.example", u, n, p, a);
    }
}

static void test_stateless_layout_is_pinned() {
    std::string priv = hexRepeat("6c", 32);
    Bytes uid = seqBytes(20, 0x21);
    uint8_t out[300];
    size_t len = 0;
    EXPECT(wrapCred("layout.example", uid.data(), 20, "dave", priv.c_str(), -8, out, sizeof out, len));
    Bytes plain = openBlob(Bytes(out, out + len));
#ifdef LEGACY_STORAGE
    EXPECT(memcmp(plain.data(), "STAT", 4) == 0);
#else
    EXPECT(memcmp(plain.data(), "STA2", 4) == 0);
    EXPECT(plain[4] == 0xFF && plain[5] == 0xFF && plain[6] == 0xFF && plain[7] == 0xF8);
    Bytes h = rpHash("layout.example");
    EXPECT(memcmp(&plain[8], h.data(), 32) == 0);
    EXPECT(plain[40] == 20);
    EXPECT(memcmp(&plain[41], uid.data(), 20) == 0);
    EXPECT(plain[61] == 4 && memcmp(&plain[62], "dave", 4) == 0);
    EXPECT(plain[66] == 0 && plain[67] == 32);
    EXPECT(hexOf(Bytes(plain.begin() + 68, plain.begin() + 100)) == priv);
    for (size_t i = 100; i < plain.size(); i++) EXPECT(plain[i] == 0);
    EXPECT(len == 16 + plain.size() + 32);
#endif
}

static void test_stateless_name_truncation_keeps_utf8_valid() {
    std::string priv = hexRepeat("7d", 32);
    Bytes uid = seqBytes(4);
    std::string name;
    for (int i = 0; i < 11; i++) name += "日";
    uint8_t out[300];
    size_t len = 0;
    EXPECT(wrapCred("utf.example", uid.data(), 4, name.c_str(), priv.c_str(), -7, out, sizeof out, len));
    String u, n, p; int a;
    EXPECT(unwrapStatelessCredential(out, len, "utf.example", u, n, p, a));
    std::string expected;
    for (int i = 0; i < 10; i++) expected += "日";
    EXPECT(n.s == expected);
    std::string emoji = std::string(30, 'a') + "😀";
    EXPECT(wrapCred("utf.example", uid.data(), 4, emoji.c_str(), priv.c_str(), -7, out, sizeof out, len));
    EXPECT(unwrapStatelessCredential(out, len, "utf.example", u, n, p, a));
    EXPECT(n.s == std::string(30, 'a'));
}

static void test_stateless_rotation_invalidates_credentials() {
    std::string priv = hexRepeat("8e", 32);
    Bytes uid = seqBytes(8);
    uint8_t out[300];
    size_t len = 0;
    EXPECT(wrapCred("rot.example", uid.data(), 8, "n", priv.c_str(), -7, out, sizeof out, len));
    String u, n, p; int a;
    EXPECT(unwrapStatelessCredential(out, len, "rot.example", u, n, p, a));
    rotateStatelessMasterSecret();
    EXPECT(!unwrapStatelessCredential(out, len, "rot.example", u, n, p, a));
    EXPECT(host_nvs()["sl_secret"].size() == 32);
}

static void test_pin_and_failure_counter_records() {
    EXPECT(!isPinSet());
    EXPECT(!createPin("123"));
    EXPECT(!isPinSet());
    EXPECT(createPin("1234"));
    EXPECT(isPinSet());
    EXPECT(fsFile("/pin.txt").size() == 64);
    EXPECT(std::string(fsFile("/pin.txt").begin(), fsFile("/pin.txt").end()) == hashPin("1234").s);
    EXPECT(verifyPin("1234"));
    EXPECT(!fsHas("/failures.txt"));
    EXPECT(!verifyPin("0000"));
    EXPECT(std::string(fsFile("/failures.txt").begin(), fsFile("/failures.txt").end()) == "1");
    EXPECT(getFailedPinAttempts() == 1);
    EXPECT(verifyPin("1234"));
    EXPECT(getFailedPinAttempts() == 0);
    for (int i = 0; i < 9; i++) verifyPin("bad");
    EXPECT(getFailedPinAttempts() == 9 && !host_restarted());
    EXPECT(!verifyPin("bad"));
    EXPECT(host_restarted());
    EXPECT(!isPinSet() && !fsHas("/failures.txt"));
    EXPECT(getFailedUvAttempts() == 0);
    incrementFailedUvAttempts();
    incrementFailedUvAttempts();
    EXPECT(getFailedUvAttempts() == 2);
    resetFailedUvAttempts();
    EXPECT(getFailedUvAttempts() == 0);
    EXPECT(getMinPinLength() == 4);
    setMinPinLength(8);
    EXPECT(getMinPinLength() == 8);
    setMinPinLength(2);
    EXPECT(getMinPinLength() == 4);
    EXPECT(!getForcePinChange());
    setForcePinChange(true);
    EXPECT(getForcePinChange());
    setForcePinChange(false);
    EXPECT(!getForcePinChange());
}

static void test_vault_and_totp_records() {
    EXPECT(!savePassword("site.com", "bob", "pw"));
    EXPECT(getPasswordFromStorage("site.com", "bob") == "");
    deriveStorageKey("1234");
    EXPECT(savePassword("site.com", "bob", "pw-one"));
    EXPECT(!savePassword("site.com", "bob", "other"));
    EXPECT(savePassword("site.com", "alice", "pw-two"));
    EXPECT(savePassword("other.com", "bob", "pw-three"));
    EXPECT(isPasswordExists("site.com", "bob"));
    EXPECT(getPasswordFromStorage("site.com", "bob") == "pw-one");
    EXPECT(getPasswordFromStorage("site.com", "alice") == "pw-two");
    EXPECT(getPasswordFromStorage("nope.com", "bob") == "");
    JsonDocument doc;
    String raw;
    raw.s.assign(fsFile("/passwords.json").begin(), fsFile("/passwords.json").end());
    EXPECT(!deserializeJson(doc, raw));
    String enc = doc["site.com"]["bob"].as<String>();
    EXPECT(enc.indexOf(':') > 0 && enc.indexOf("pw-one") < 0 && raw.indexOf("pw-one") < 0);
    EXPECT(!savePassword(String(std::string(65, 'w').c_str()), "bob", "x"));
    EXPECT(!savePassword("long.com", "bob", String(std::string(4001, 'p').c_str())));
    EXPECT(savePassword("long.com", "bob", String(std::string(4000, 'p').c_str())));
    EXPECT(getPasswordFromStorage("long.com", "bob").length() == 4000);
    deriveStorageKey("9999");
    EXPECT(getPasswordFromStorage("site.com", "bob") == "");
    deriveStorageKey("1234");
    EXPECT(deletePassword("site.com", "bob"));
    EXPECT(!deletePassword("site.com", "bob"));
    EXPECT(getPasswordFromStorage("site.com", "alice") == "pw-two");
    EXPECT(deletePassword("site.com", "alice"));
    raw.s.assign(fsFile("/passwords.json").begin(), fsFile("/passwords.json").end());
    deserializeJson(doc, raw);
    EXPECT(!doc["site.com"].is<JsonObject>());
    clearStorageKey();
    EXPECT(getPasswordFromStorage("other.com", "bob") == "");
    deriveStorageKey("1234");
    saveTotpSecret("github", "JBSWY3DPEHPK3PXP");
    EXPECT(getTotpSecret("github") == "JBSWY3DPEHPK3PXP");
    EXPECT(getTotpSecret("missing") == "");
    raw.s.assign(fsFile("/totp.json").begin(), fsFile("/totp.json").end());
    EXPECT(raw.indexOf("JBSWY3DPEHPK3PXP") < 0);
    EXPECT(deleteTotpSecret("github"));
    EXPECT(getTotpSecret("github") == "");
}

static void test_largeblob_and_resets() {
    uint8_t *d = nullptr; size_t l = 5;
    EXPECT(!getLargeBlobArray(&d, l));
    EXPECT(setLargeBlobArray(nullptr, 0));
    EXPECT(getLargeBlobArray(&d, l) && l == 0);
    free(d);
    Bytes blob = seqBytes(1000);
    EXPECT(setLargeBlobArray(blob.data(), blob.size()));
    EXPECT(getLargeBlobArray(&d, l) && l == 1000 && memcmp(d, blob.data(), 1000) == 0);
    free(d);

    std::vector<const char *> files = {"/passwords.json", "/passkeys.json", "/passkeys.bin", "/passkeys.tmp", "/totp.json", "/pin.txt", "/failures.txt", "/crypto_alg.txt", "/largeblob.bin", "/fido_uv_fail.txt", "/fido_force_pin.txt", "/fido_min_pin.txt", "/bio_templates.json"};
    for (auto f : files) fsFile(f) = Bytes{'x'};
    fsFile("/keepme.txt") = Bytes{'k'};
    factoryResetSystem();
    for (auto f : files) EXPECT(!fsHas(f));
    EXPECT(fsHas("/keepme.txt"));

    for (auto f : files) fsFile(f) = Bytes{'x'};
    uint8_t secret[32] = {1};
    nvs_set_blob(0, "sl_secret", secret, 32);
    Bytes oldSecret = host_nvs()["sl_secret"];
    resetFido2System();
    for (auto f : files) EXPECT(!fsHas(f));
    EXPECT(host_nvs()["sl_secret"] != oldSecret);
}

int main() {
    RUN(test_passkey_roundtrip);
    RUN(test_passkey_username_special_chars);
    RUN(test_passkey_legacy_payloads_still_readable);
    RUN(test_passkey_record_layout);
    RUN(test_passkey_multi_record_operations);
    RUN(test_passkey_website_info_listing);
    RUN(test_passkey_truncation_sweep);
    RUN(test_passkey_corrupt_length_fields);
    RUN(test_passkey_random_corruption_is_safe);
    RUN(test_passkey_oversized_fields_rejected);
    RUN(test_stateless_roundtrip_matrix);
    RUN(test_stateless_rejects_bad_inputs);
    RUN(test_stateless_tamper_and_truncation);
    RUN(test_stateless_legacy_v1_compatibility);
    RUN(test_stateless_forged_authentic_blobs);
    RUN(test_stateless_layout_is_pinned);
    RUN(test_stateless_name_truncation_keeps_utf8_valid);
    RUN(test_stateless_rotation_invalidates_credentials);
    RUN(test_pin_and_failure_counter_records);
    RUN(test_vault_and_totp_records);
    RUN(test_largeblob_and_resets);
    printf("\n%d assertions passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
