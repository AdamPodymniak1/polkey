#include "Arduino.h"
#include "CtapValidate.h"
#include <random>
#include <string>
#include <vector>

static int g_fail = 0, g_pass = 0;
#define EXPECT_EQ(a, b) do { auto va = (a); auto vb = (b); if (va != vb) { g_fail++; printf("    FAIL %s:%d  %s -> 0x%02X, expected 0x%02X\n", __FILE__, __LINE__, #a, (unsigned)va, (unsigned)vb); } else g_pass++; } while (0)

typedef std::vector<uint8_t> B;

static void head(B &o, int major, uint64_t v) {
    if (v < 24) o.push_back((major << 5) | v);
    else if (v < 256) { o.push_back((major << 5) | 24); o.push_back(v); }
    else { o.push_back((major << 5) | 25); o.push_back(v >> 8); o.push_back(v & 0xFF); }
}
static B uintv(uint64_t v) { B o; head(o, 0, v); return o; }
static B intv(int64_t v) { B o; if (v >= 0) head(o, 0, v); else head(o, 1, -1 - v); return o; }
static B text(const std::string &s) { B o; head(o, 3, s.size()); o.insert(o.end(), s.begin(), s.end()); return o; }
static B bytes(size_t n) { B o; head(o, 2, n); for (size_t i = 0; i < n; i++) o.push_back(0x11); return o; }
static B boolv(bool b) { return B{(uint8_t)(b ? 0xF5 : 0xF4)}; }
static B cat(std::initializer_list<B> parts) { B o; for (auto &p : parts) o.insert(o.end(), p.begin(), p.end()); return o; }
static B map(std::vector<std::pair<B, B>> kv) { B o; head(o, 5, kv.size()); for (auto &e : kv) { o.insert(o.end(), e.first.begin(), e.first.end()); o.insert(o.end(), e.second.begin(), e.second.end()); } return o; }
static B arr(std::vector<B> items) { B o; head(o, 4, items.size()); for (auto &i : items) o.insert(o.end(), i.begin(), i.end()); return o; }

static B rpOk() { return map({{text("id"), text("example.org")}, {text("name"), text("Example")}}); }
static B userOk() { return map({{text("id"), bytes(8)}, {text("name"), text("alice")}, {text("displayName"), text("Alice")}}); }
static B paramsOk() { return arr({map({{text("alg"), intv(-7)}, {text("type"), text("public-key")}})}); }

struct Mc {
    B cdh = bytes(32), rp = rpOk(), user = userOk(), params = paramsOk();
    B exclude, ext, opts, pinAuth, pinProto;
    bool noCdh = false, noRp = false, noUser = false, noParams = false;
    B build() const {
        std::vector<std::pair<B, B>> kv;
        if (!noCdh) kv.push_back({uintv(1), cdh});
        if (!noRp) kv.push_back({uintv(2), rp});
        if (!noUser) kv.push_back({uintv(3), user});
        if (!noParams) kv.push_back({uintv(4), params});
        if (!exclude.empty()) kv.push_back({uintv(5), exclude});
        if (!ext.empty()) kv.push_back({uintv(6), ext});
        if (!opts.empty()) kv.push_back({uintv(7), opts});
        if (!pinAuth.empty()) kv.push_back({uintv(8), pinAuth});
        if (!pinProto.empty()) kv.push_back({uintv(9), pinProto});
        return map(kv);
    }
};
static uint8_t mc(const Mc &m) { B b = m.build(); return ctapValidateMakeCredential(b.data(), b.size()); }

struct Ga {
    B rp = text("example.org"), cdh = bytes(32), allow, ext, opts, pinAuth, pinProto;
    bool noRp = false, noCdh = false;
    B build() const {
        std::vector<std::pair<B, B>> kv;
        if (!noRp) kv.push_back({uintv(1), rp});
        if (!noCdh) kv.push_back({uintv(2), cdh});
        if (!allow.empty()) kv.push_back({uintv(3), allow});
        if (!ext.empty()) kv.push_back({uintv(4), ext});
        if (!opts.empty()) kv.push_back({uintv(5), opts});
        if (!pinAuth.empty()) kv.push_back({uintv(6), pinAuth});
        if (!pinProto.empty()) kv.push_back({uintv(7), pinProto});
        return map(kv);
    }
};
static uint8_t ga(const Ga &g) { B b = g.build(); return ctapValidateGetAssertion(b.data(), b.size()); }

static B desc(const B &type, const B &id) { return map({{text("type"), type}, {text("id"), id}}); }

static void test_make_credential() {
    EXPECT_EQ(mc(Mc()), 0);
    { Mc m; m.noCdh = true; EXPECT_EQ(mc(m), 0x14); }
    { Mc m; m.noRp = true; EXPECT_EQ(mc(m), 0x14); }
    { Mc m; m.noUser = true; EXPECT_EQ(mc(m), 0x14); }
    { Mc m; m.noParams = true; EXPECT_EQ(mc(m), 0x14); }
    { Mc m; m.cdh = uintv(5); EXPECT_EQ(mc(m), 0x11); }
    { Mc m; m.cdh = bytes(31); EXPECT_EQ(mc(m), 0x02); }
    { Mc m; m.user = bytes(9); EXPECT_EQ(mc(m), 0x11); }
    { Mc m; m.rp = bytes(10); EXPECT_EQ(mc(m), 0x11); }
    { Mc m; m.params = bytes(5); EXPECT_EQ(mc(m), 0x11); }
    { Mc m; m.exclude = uintv(8); EXPECT_EQ(mc(m), 0x11); }
    { Mc m; m.ext = uintv(8); EXPECT_EQ(mc(m), 0x11); }
    { Mc m; m.opts = uintv(8); EXPECT_EQ(mc(m), 0x11); }
    { Mc m; m.rp = map({{text("id"), text("test.org")}, {text("name"), uintv(8)}}); EXPECT_EQ(mc(m), 0x11); }
    { Mc m; m.rp = map({{text("id"), uintv(8)}, {text("name"), text("n")}}); EXPECT_EQ(mc(m), 0x11); }
    { Mc m; m.rp = map({{text("id"), text("test.org")}, {text("icon"), uintv(8)}}); EXPECT_EQ(mc(m), 0x11); }
    { Mc m; m.rp = map({{text("name"), text("n")}}); EXPECT_EQ(mc(m), 0x14); }
    { Mc m; m.user = map({{text("id"), bytes(7)}, {text("name"), uintv(8)}}); EXPECT_EQ(mc(m), 0x11); }
    { Mc m; m.user = map({{text("id"), text("user_id")}, {text("name"), text("n")}}); EXPECT_EQ(mc(m), 0x11); }
    { Mc m; m.user = map({{text("id"), bytes(7)}, {text("displayName"), uintv(8)}}); EXPECT_EQ(mc(m), 0x11); }
    { Mc m; m.user = map({{text("id"), bytes(7)}, {text("icon"), uintv(8)}}); EXPECT_EQ(mc(m), 0x11); }
    { Mc m; m.user = map({{text("id"), bytes(65)}}); EXPECT_EQ(mc(m), 0x02); }
    { Mc m; m.user = map({{text("id"), bytes(64)}}); EXPECT_EQ(mc(m), 0); }
    { Mc m; m.user = map({{text("name"), text("x")}}); EXPECT_EQ(mc(m), 0x14); }
    { Mc m; m.params = arr({text("wrong")}); EXPECT_EQ(mc(m), 0x11); }
    { Mc m; m.params = arr({map({{text("alg"), intv(-7)}})}); EXPECT_EQ(mc(m), 0x14); }
    { Mc m; m.params = arr({map({{text("type"), text("public-key")}})}); EXPECT_EQ(mc(m), 0x14); }
    { Mc m; m.params = arr({map({{text("alg"), text("7")}, {text("type"), text("public-key")}})}); EXPECT_EQ(mc(m), 0x11); }
    { Mc m; m.params = arr({map({{text("alg"), intv(1337)}, {text("type"), text("public-key")}})}); EXPECT_EQ(mc(m), 0x26); }
    { Mc m; m.params = arr({}); EXPECT_EQ(mc(m), 0x26); }
    { Mc m; m.params = arr({map({{text("alg"), intv(-7)}, {text("type"), text("rot13")}})}); EXPECT_EQ(mc(m), 0x26); }
    { Mc m; m.params = arr({map({{text("alg"), intv(1337)}, {text("type"), text("public-key")}}), map({{text("alg"), intv(-8)}, {text("type"), text("public-key")}})}); EXPECT_EQ(mc(m), 0); }
    { Mc m; m.params = arr({map({{text("alg"), intv(-48)}, {text("type"), text("public-key")}})}); EXPECT_EQ(mc(m), 0); }
    { Mc m; m.exclude = arr({desc(text("rot13"), bytes(4))}); EXPECT_EQ(mc(m), 0); }
    { Mc m; m.exclude = arr({desc(text("mangoPapayaCoconutNotAPublicKey"), bytes(4))}); EXPECT_EQ(mc(m), 0); }
    { Mc m; m.exclude = arr({text("1234")}); EXPECT_EQ(mc(m), 0x11); }
    { Mc m; m.exclude = arr({map({{text("id"), bytes(4)}})}); EXPECT_EQ(mc(m), 0x14); }
    { Mc m; m.exclude = arr({map({{text("type"), text("public-key")}})}); EXPECT_EQ(mc(m), 0x14); }
    { Mc m; m.exclude = arr({desc(text("public-key"), text("1234"))}); EXPECT_EQ(mc(m), 0x11); }
    { Mc m; m.exclude = arr({desc(bytes(10), bytes(4))}); EXPECT_EQ(mc(m), 0x11); }
    { Mc m; m.exclude = arr({desc(text("public-key"), bytes(4)), desc(text("public-key"), bytes(200))}); EXPECT_EQ(mc(m), 0); }
    { Mc m; m.opts = map({{text("unknown"), boolv(false)}}); EXPECT_EQ(mc(m), 0); }
    { Mc m; m.opts = map({{text("rk"), boolv(true)}, {text("uv"), boolv(false)}}); EXPECT_EQ(mc(m), 0); }
    { Mc m; m.opts = map({{text("up"), boolv(false)}}); EXPECT_EQ(mc(m), 0x2C); }
    { Mc m; m.opts = map({{text("up"), boolv(true)}}); EXPECT_EQ(mc(m), 0x2C); }
    { Mc m; m.opts = map({{text("rk"), uintv(1)}}); EXPECT_EQ(mc(m), 0x11); }
    { Mc m; m.opts = map({{uintv(1), boolv(true)}}); EXPECT_EQ(mc(m), 0x11); }
    { Mc m; m.ext = map({{text("hmac-secret"), boolv(true)}, {text("credProtect"), uintv(2)}}); EXPECT_EQ(mc(m), 0); }
    { Mc m; m.pinAuth = bytes(16); m.pinProto = uintv(1); EXPECT_EQ(mc(m), 0); }
    { Mc m; m.pinAuth = text("x"); EXPECT_EQ(mc(m), 0x11); }
    { Mc m; m.pinProto = text("1"); EXPECT_EQ(mc(m), 0x11); }
    { B b = Mc().build(); b.push_back(0x00); EXPECT_EQ(ctapValidateMakeCredential(b.data(), b.size()), 0x12); }
    { B b = Mc().build(); b.pop_back(); EXPECT_EQ(ctapValidateMakeCredential(b.data(), b.size()), 0x12); }
    EXPECT_EQ(ctapValidateMakeCredential(nullptr, 0), 0x14);
    { B b = arr({}); EXPECT_EQ(ctapValidateMakeCredential(b.data(), b.size()), 0x11); }
    { B b = {0xBF, 0xFF}; EXPECT_EQ(ctapValidateMakeCredential(b.data(), b.size()), 0x12); }
    { B b = map({}); EXPECT_EQ(ctapValidateMakeCredential(b.data(), b.size()), 0x14); }
}

static void test_get_assertion() {
    EXPECT_EQ(ga(Ga()), 0);
    { Ga g; g.noRp = true; EXPECT_EQ(ga(g), 0x14); }
    { Ga g; g.noCdh = true; EXPECT_EQ(ga(g), 0x14); }
    { Ga g; g.rp = bytes(4); EXPECT_EQ(ga(g), 0x11); }
    { Ga g; g.cdh = text("x"); EXPECT_EQ(ga(g), 0x11); }
    { Ga g; g.cdh = bytes(20); EXPECT_EQ(ga(g), 0x02); }
    { Ga g; g.allow = arr({desc(text("public-key"), bytes(16))}); EXPECT_EQ(ga(g), 0); }
    { Ga g; g.allow = arr({desc(text("rot13"), bytes(16))}); EXPECT_EQ(ga(g), 0); }
    { Ga g; g.allow = arr({map({{text("type"), text("public-key")}})}); EXPECT_EQ(ga(g), 0x14); }
    { Ga g; g.allow = arr({map({{text("id"), bytes(8)}})}); EXPECT_EQ(ga(g), 0x14); }
    { Ga g; g.allow = arr({desc(text("public-key"), text("id"))}); EXPECT_EQ(ga(g), 0x11); }
    { Ga g; g.allow = arr({desc(uintv(1), bytes(8))}); EXPECT_EQ(ga(g), 0x11); }
    { Ga g; g.allow = arr({text("x")}); EXPECT_EQ(ga(g), 0x11); }
    { Ga g; g.allow = uintv(3); EXPECT_EQ(ga(g), 0x11); }
    { Ga g; g.opts = map({{text("up"), boolv(false)}}); EXPECT_EQ(ga(g), 0); }
    { Ga g; g.opts = map({{text("up"), uintv(0)}}); EXPECT_EQ(ga(g), 0x11); }
    { Ga g; g.opts = uintv(1); EXPECT_EQ(ga(g), 0x11); }
    { Ga g; g.ext = uintv(1); EXPECT_EQ(ga(g), 0x11); }
    { Ga g; g.pinAuth = bytes(16); g.pinProto = uintv(1); EXPECT_EQ(ga(g), 0); }
    { Ga g; g.pinAuth = uintv(1); EXPECT_EQ(ga(g), 0x11); }
    { B b = Ga().build(); b.push_back(0xFF); EXPECT_EQ(ctapValidateGetAssertion(b.data(), b.size()), 0x12); }
}

static void test_mutation_fuzz() {
    std::mt19937_64 rng(12345);
    std::vector<B> seeds;
    { Mc m; m.exclude = arr({desc(text("public-key"), bytes(32))}); m.ext = map({{text("hmac-secret"), boolv(true)}}); m.opts = map({{text("rk"), boolv(true)}}); m.pinAuth = bytes(16); m.pinProto = uintv(1); seeds.push_back(m.build()); }
    { Ga g; g.allow = arr({desc(text("public-key"), bytes(32))}); g.ext = map({{text("hmac-secret"), map({{uintv(1), bytes(64)}})}}); g.opts = map({{text("up"), boolv(true)}}); g.pinAuth = bytes(16); g.pinProto = uintv(1); seeds.push_back(g.build()); }
    long accepted = 0, total = 0;
    for (int iter = 0; iter < 400000; iter++) {
        B b = seeds[rng() % seeds.size()];
        int edits = 1 + rng() % 4;
        for (int e = 0; e < edits && !b.empty(); e++) {
            switch (rng() % 5) {
                case 0: b[rng() % b.size()] = rng(); break;
                case 1: b[rng() % b.size()] ^= 1 << (rng() % 8); break;
                case 2: b.resize(rng() % (b.size() + 1)); break;
                case 3: b.insert(b.begin() + rng() % (b.size() + 1), (uint8_t)rng()); break;
                case 4: if (b.size() > 1) b.erase(b.begin() + rng() % b.size()); break;
            }
        }
        uint8_t r1 = ctapValidateMakeCredential(b.data(), b.size());
        uint8_t r2 = ctapValidateGetAssertion(b.data(), b.size());
        total += 2;
        accepted += (r1 == 0) + (r2 == 0);
        bool known = (r1 == 0 || r1 == 0x02 || r1 == 0x11 || r1 == 0x12 || r1 == 0x14 || r1 == 0x26 || r1 == 0x2C) &&
                     (r2 == 0 || r2 == 0x02 || r2 == 0x11 || r2 == 0x12 || r2 == 0x14 || r2 == 0x26 || r2 == 0x2C);
        if (!known) { g_fail++; printf("    FAIL unknown code\n"); break; }
        g_pass++;
    }
    printf("    fuzz: %ld validations, %ld accepted\n", total, accepted);
}

int main() {
    test_make_credential();
    test_get_assertion();
    test_mutation_fuzz();
    printf("\n%d assertions passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
