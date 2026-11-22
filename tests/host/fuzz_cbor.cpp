#include "CborEngine.h"
#include <vector>
#include <string>
#include <chrono>
#include <random>

static int g_violations = 0;
#define CHECK(cond, ...) do { if (!(cond)) { g_violations++; fprintf(stderr, "VIOLATION %s:%d: %s ", __FILE__, __LINE__, #cond); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); abort(); } } while (0)
static bool refItem(const uint8_t *b, size_t n, size_t &o, int depth) {
    if (depth > 16) return false;
    if (o >= n) return false;
    uint8_t ib = b[o++];
    int mt = ib >> 5, ai = ib & 31;
    uint64_t v = 0;
    if (ai < 24) {
        v = ai;
    } else if (ai == 24) {
        if (o + 1 > n) return false;
        v = b[o++];
        if (v < 24) return false;
    } else if (ai == 25) {
        if (o + 2 > n) return false;
        v = ((uint64_t)b[o] << 8) | b[o + 1];
        o += 2;
        if (v <= 0xFF) return false;
    } else if (ai == 26) {
        if (o + 4 > n) return false;
        v = 0;
        for (int i = 0; i < 4; i++) v = (v << 8) | b[o++];
        if (v <= 0xFFFF) return false;
    } else if (ai == 27) {
        if (o + 8 > n) return false;
        v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | b[o++];
        if (v <= 0xFFFFFFFFull) return false;
    } else {
        return false;
    }
    switch (mt) {
        case 0:
        case 1:
            return true;
        case 2:
        case 3:
            if (v > n - o) return false;
            o += v;
            return true;
        case 4:
            if (v > 256) return false;
            for (uint64_t i = 0; i < v; i++) if (!refItem(b, n, o, depth + 1)) return false;
            return true;
        case 5:
            if (v > 256) return false;
            for (uint64_t i = 0; i < v * 2; i++) if (!refItem(b, n, o, depth + 1)) return false;
            return true;
        case 6:
            return false;
        default:
            return ai >= 20 && ai <= 22;
    }
}

static void walk(const uint8_t *data, size_t len, uint32_t choice) {
    uint8_t *buf = (uint8_t *)malloc(len ? len : 1);
    if (len) memcpy(buf, data, len);
    CborParser p(buf, len);
    CHECK(p.getOffset() == 0, "init");

    uint8_t t; uint64_t v;
    size_t before = p.getOffset();
    if (p.readTypeAndValue(t, v)) {
        CHECK(t != 6, "tag accepted");
        if (t == 7) CHECK(v >= 20 && v <= 22, "simple/float value %llu accepted", (unsigned long long)v);
        CHECK(p.getOffset() > before, "no progress");
        CHECK(p.getOffset() <= len, "offset %zu > len %zu", p.getOffset(), len);
        if (t == 5 || t == 4) {
            uint64_t n = (t == 5) ? v * 2 : v;
            if (v == 0xFFFFFFFFFFFFFFFFULL || n > 600) n = 600;
            for (uint64_t i = 0; i < n && !p.isFinished(); i++) {
                size_t o = p.getOffset();
                uint32_t pick = (choice >> ((i * 2) & 15)) & 3;
                bool ok;
                if (pick == 0) {
                    char *dst = (char *)malloc(8);
                    ok = p.readTextString(dst, 8);
                    if (ok) CHECK(strlen(dst) < 8, "text not terminated");
                    free(dst);
                } else if (pick == 1) {
                    uint8_t *dst = (uint8_t *)malloc(32); size_t al = 0;
                    ok = p.readByteString(dst, 32, al);
                    if (ok) CHECK(al <= 32, "alen %zu", al);
                    free(dst);
                } else if (pick == 2) {
                    uint8_t t2; uint64_t v2;
                    ok = p.readTypeAndValue(t2, v2);
                    if (ok) CHECK(t2 != 6 && (t2 != 7 || (v2 >= 20 && v2 <= 22)), "bad major type accepted");
                } else {
                    ok = p.skipValue();
                }
                CHECK(p.getOffset() <= len, "offset past end");
                if (ok) CHECK(p.getOffset() > o, "success w/o progress (pick %u)", pick);
                else if (pick != 3 && pick != 2) CHECK(p.getOffset() == o, "failed read moved offset (pick %u)", pick);
                if (!ok) break;
            }
        }
    }
    {
        CborParser d(buf, len);
        bool got = d.skipValue();
        size_t gotOff = d.getOffset();
        size_t refOff = 0;
        bool want = refItem(buf, len, refOff, 0);
        CHECK(got == want, "parser %s but reference %s (len %zu)", got ? "accepts" : "rejects", want ? "accepts" : "rejects", len);
        if (got) CHECK(gotOff == refOff, "offset %zu vs reference %zu", gotOff, refOff);
    }
    CborParser q(buf, len);
    for (int guard = 0; guard < 100000 && !q.isFinished(); guard++) {
        size_t o = q.getOffset();
        bool ok = q.skipValue();
        CHECK(q.getOffset() <= len, "skip offset past end");
        if (!ok) break;
        CHECK(q.getOffset() > o, "skip no progress");
    }
    (void)q.peekMajorType();
    free(buf);
}

static void encoder_roundtrip(std::mt19937 &rng) {
    size_t cap = 1 + rng() % 300;
    uint8_t *buf = (uint8_t *)malloc(cap);
    CborEncoder e(buf, cap);
    struct Item { int kind; uint64_t u; std::string s; };
    std::vector<Item> items;
    for (int i = 0; i < 12; i++) {
        int k = rng() % 6; Item it{k, 0, ""};
        bool ok = false;
        switch (k) {
            case 0: it.u = ((uint64_t)rng() << 32 | rng()) >> (rng() % 64); ok = e.writeUnsignedInt(it.u); break;
            case 1: { int64_t n = -1 - (int64_t)(((uint64_t)rng() << 32 | rng()) >> (1 + rng() % 63)); it.u = (uint64_t)n; ok = e.writeNegativeInt(n); break; }
            case 2: { it.s.resize(rng() % 40); for (auto &c : it.s) c = rng(); ok = e.writeByteString((const uint8_t *)it.s.data(), it.s.size()); break; }
            case 3: { it.s.resize(rng() % 40); for (auto &c : it.s) c = 'a' + rng() % 26; ok = e.writeTextString(it.s.c_str()); break; }
            case 4: it.u = rng() & 1; ok = e.writeBoolean(it.u); break;
            case 5: ok = e.writeNull(); break;
        }
        CHECK(e.getOffset() <= cap, "encoder wrote past capacity");
        if (!ok) break;
        items.push_back(it);
    }
    CborParser p(buf, e.getOffset());
    for (auto &it : items) {
        uint8_t t; uint64_t v;
        switch (it.kind) {
            case 0: CHECK(p.readTypeAndValue(t, v) && t == 0 && v == it.u, "uint rt"); break;
            case 1: CHECK(p.readTypeAndValue(t, v) && t == 1 && (int64_t)(-1 - (int64_t)v) == (int64_t)it.u, "nint rt"); break;
            case 2: { uint8_t d[64]; size_t l; CHECK(p.readByteString(d, sizeof d, l) && l == it.s.size() && !memcmp(d, it.s.data(), l), "bstr rt"); break; }
            case 3: { char d[64]; CHECK(p.readTextString(d, sizeof d) && it.s == d, "tstr rt"); break; }
            case 4: CHECK(p.readTypeAndValue(t, v) && t == 7 && v == (it.u ? 21u : 20u), "bool rt"); break;
            case 5: CHECK(p.readTypeAndValue(t, v) && t == 7 && v == 22, "null rt"); break;
        }
    }
    CHECK(p.isFinished(), "trailing bytes after round trip");
    free(buf);
}

static std::vector<std::vector<uint8_t>> seeds() {
    std::vector<std::vector<uint8_t>> s;
    auto mk = [&](auto fn) { uint8_t b[512]; CborEncoder e(b, sizeof b); fn(e); s.emplace_back(b, b + e.getOffset()); };
    mk([](CborEncoder &e) {
        e.writeMapHeader(5);
        e.writeUnsignedInt(1); uint8_t h[32] = {1}; e.writeByteString(h, 32);
        e.writeUnsignedInt(2); e.writeMapHeader(2); e.writeTextString("id"); e.writeTextString("example.com"); e.writeTextString("name"); e.writeTextString("Example");
        e.writeUnsignedInt(3); e.writeMapHeader(3); e.writeTextString("id"); e.writeByteString(h, 16); e.writeTextString("name"); e.writeTextString("u"); e.writeTextString("displayName"); e.writeTextString("U");
        e.writeUnsignedInt(4); e.writeArrayHeader(2);
        e.writeMapHeader(2); e.writeTextString("alg"); e.writeNegativeInt(-7); e.writeTextString("type"); e.writeTextString("public-key");
        e.writeMapHeader(2); e.writeTextString("alg"); e.writeNegativeInt(-257); e.writeTextString("type"); e.writeTextString("public-key");
        e.writeUnsignedInt(7); e.writeMapHeader(2); e.writeTextString("rk"); e.writeBoolean(true); e.writeTextString("uv"); e.writeBoolean(false);
    });
    mk([](CborEncoder &e) {
        e.writeMapHeader(4);
        e.writeUnsignedInt(1); e.writeTextString("example.com");
        e.writeUnsignedInt(2); uint8_t h[32] = {2}; e.writeByteString(h, 32);
        e.writeUnsignedInt(4); e.writeMapHeader(2);
        e.writeTextString("hmac-secret"); e.writeMapHeader(2); e.writeUnsignedInt(1); e.writeByteString(h, 32); e.writeUnsignedInt(2); e.writeByteString(h, 32);
        e.writeTextString("largeBlobKey"); e.writeBoolean(true);
        e.writeUnsignedInt(5); e.writeMapHeader(1); e.writeTextString("up"); e.writeBoolean(false);
    });
    auto raw = [&](std::initializer_list<uint8_t> l) { s.emplace_back(l); };
    raw({0xBF, 0x01, 0x02, 0xFF});
    raw({0x9F, 0x01, 0x02, 0xFF});
    raw({0x5F, 0x41, 0x00, 0xFF});
    raw({0x7F, 0x61, 'a', 0xFF});
    raw({0xFF});
    raw({0xBF, 0xFF});
    raw({0x5B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF});
    raw({0x7B, 0x80, 0, 0, 0, 0, 0, 0, 0});
    raw({0xB9, 0xFF, 0xFF});
    raw({0xA1, 0x00, 0xC1, 0x00});
    raw({0xF9, 0x3C, 0x00});
    raw({0xFB, 0x3F, 0xF0, 0, 0, 0, 0, 0, 0});
    raw({0xFC});  raw({0xFD}); raw({0xFE}); raw({0x1C}); raw({0x1F}); raw({0x3F}); raw({0x5C});
    { std::vector<uint8_t> v(40, 0x81); v.push_back(0x00); s.push_back(v); }
    { std::vector<uint8_t> v(40, 0x9F); s.push_back(v); }
    { std::vector<uint8_t> v; for (int i = 0; i < 20; i++) v.push_back(0xA1), v.push_back(0x00); v.push_back(0x00); s.push_back(v); }
    return s;
}

static void mutate(std::vector<uint8_t> &d, std::mt19937 &rng) {
    static const uint8_t interesting[] = {0x00, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1F, 0x3F, 0x5F, 0x7F, 0x9F, 0xBF, 0xFF, 0x80, 0xA0, 0xC0, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC};
    int n = 1 + rng() % 4;
    for (int i = 0; i < n; i++) {
        switch (rng() % 7) {
            case 0: if (!d.empty()) d[rng() % d.size()] ^= 1 << (rng() % 8); break;
            case 1: if (!d.empty()) d[rng() % d.size()] = rng(); break;
            case 2: if (!d.empty()) d[rng() % d.size()] = interesting[rng() % sizeof interesting]; break;
            case 3: d.insert(d.begin() + (d.empty() ? 0 : rng() % (d.size() + 1)), interesting[rng() % sizeof interesting]); break;
            case 4: if (!d.empty()) d.erase(d.begin() + rng() % d.size()); break;
            case 5: if (!d.empty()) d.resize(rng() % d.size()); break;
            case 6: if (d.size() > 1 && d.size() < 4096) { size_t a = rng() % d.size(), b = rng() % d.size(); size_t l = 1 + rng() % 16; for (size_t k = 0; k < l && a + k < d.size() && b + k < d.size(); k++) d[a + k] = d[b + k]; } break;
        }
    }
}

#ifdef LIBFUZZER
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    walk(data, size, size ? data[0] * 2654435761u : 0);
    return 0;
}
#else
int main(int argc, char **argv) {
    long iters = argc > 1 ? atol(argv[1]) : 2000000;
    uint32_t seed = argc > 2 ? (uint32_t)atol(argv[2]) : 12345;
    std::mt19937 rng(seed);
    auto corpus = seeds();
    double worst = 0; size_t worstLen = 0;
    for (long i = 0; i < iters; i++) {
        std::vector<uint8_t> d = corpus[rng() % corpus.size()];
        if (rng() % 8 == 0) { d.resize(rng() % 64); for (auto &b : d) b = rng(); }
        mutate(d, rng);
        if (d.size() > 1024) d.resize(1024);
        auto t0 = std::chrono::steady_clock::now();
        walk(d.data(), d.size(), rng());
        double ms = std::chrono::duration<double, std::milli>(t0 - t0 + (std::chrono::steady_clock::now() - t0)).count();
        if (ms > worst) { worst = ms; worstLen = d.size(); }
        CHECK(ms < 200.0, "input of %zu bytes took %.1f ms (algorithmic DoS?)", d.size(), ms);
        if (rng() % 4 == 0 && corpus.size() < 4000) corpus.push_back(d);
        if (i % 16 == 0) encoder_roundtrip(rng);
    }
    printf("fuzz_cbor: %ld iterations, seed %u, corpus %zu, slowest %.3f ms (%zu bytes), violations %d\n",
           iters, seed, corpus.size(), worst, worstLen, g_violations);
    return 0;
}
#endif
