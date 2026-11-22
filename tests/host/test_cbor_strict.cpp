#include "CborEngine.h"
#include <vector>

struct Case { const char *name; std::vector<uint8_t> in; bool shouldAccept; };

static bool skipsWhole(const std::vector<uint8_t> &v) {
    CborParser p(v.data(), v.size());
    return p.skipValue() && p.isFinished();
}

int main() {
    std::vector<Case> cases = {
        {"empty map",                         {0xA0}, true},
        {"uint 1",                            {0x01}, true},
        {"definite array [1,2]",              {0x82, 0x01, 0x02}, true},
        {"truncated array [1,2]",             {0x82, 0x01}, false},
        {"truncated bstr",                    {0x45, 1, 2}, false},
        {"indefinite array",                  {0x9F, 0x01, 0xFF}, false},
        {"indefinite map",                    {0xBF, 0x01, 0x02, 0xFF}, false},
        {"indefinite bstr",                   {0x5F, 0x41, 0x00, 0xFF}, false},
        {"indefinite tstr",                   {0x7F, 0x61, 'a', 0xFF}, false},
        {"stray break as a value",            {0xFF}, false},
        {"uint with indefinite marker (0x1F)",{0x1F}, false},
        {"nint with indefinite marker (0x3F)",{0x3F}, false},
        {"simple value w/ ai 31 (0xFF-like 0xFF)", {0xFF}, false},
        {"reserved additional info 28",       {0x1C}, false},
        {"tag",                               {0xC1, 0x00}, false},
        {"float16",                           {0xF9, 0x3C, 0x00}, false},
        {"non-minimal uint (0x18 0x01)",      {0x18, 0x01}, false},
        {"non-minimal uint (0x19 0x00 0xFF)", {0x19, 0x00, 0xFF}, false},
        {"map of 257 entries (over limit)",   {0xB9, 0x01, 0x01}, false},
        {"depth 17 nesting",                  std::vector<uint8_t>(17, 0x81), false},
        {"true",                              {0xF5}, true},
        {"false",                             {0xF4}, true},
        {"null",                              {0xF6}, true},
        {"undefined",                         {0xF7}, false},
        {"simple value 1-byte",               {0xF8, 0x20}, false},
        {"uint 24 minimal",                   {0x18, 0x18}, true},
        {"uint 256 minimal",                  {0x19, 0x01, 0x00}, true},
        {"uint 65536 minimal",                {0x1A, 0x00, 0x01, 0x00, 0x00}, true},
        {"uint 2^32 minimal",                 {0x1B, 0, 0, 0, 1, 0, 0, 0, 0}, true},
        {"non-minimal uint32 (0x1A 0 0 0xFF 0xFF)", {0x1A, 0x00, 0x00, 0xFF, 0xFF}, false},
        {"non-minimal uint64 (fits in 32)",   {0x1B, 0, 0, 0, 0, 0, 0, 0x01, 0x00}, false},
        {"nint -1",                           {0x20}, true},
        {"nint -25 minimal",                  {0x38, 0x18}, true},
        {"non-minimal nint (0x38 0x05)",      {0x38, 0x05}, false},
        {"empty bstr",                        {0x40}, true},
        {"bstr len non-minimal (0x58 0x01 x)",{0x58, 0x01, 0x00}, false},
        {"bstr 24 bytes minimal",             [] { std::vector<uint8_t> v{0x58, 0x18}; v.resize(26, 0); return v; }(), true},
        {"tstr 'a'",                          {0x61, 'a'}, true},
        {"map {1:2}",                         {0xA1, 0x01, 0x02}, true},
        {"map missing value",                 {0xA1, 0x01}, false},
        {"nested depth 16",                   [] { std::vector<uint8_t> v(16, 0x81); v.push_back(0x00); return v; }(), true},
        {"array of 256",                      [] { std::vector<uint8_t> v{0x99, 0x01, 0x00}; v.resize(3 + 256, 0x00); return v; }(), true},
    };
    int deviations = 0;
    for (auto &c : cases) {
        const std::vector<uint8_t> &in = c.in;
        bool got = skipsWhole(in);
        const char *tag = (got == c.shouldAccept) ? "ok       " : "DEVIATION";
        if (got != c.shouldAccept) deviations++;
        printf("[%s] %-42s expected %-6s got %s\n", tag, c.name, c.shouldAccept ? "accept" : "reject", got ? "accept" : "reject");
    }
    printf("\n%d deviation(s) from CTAP2 canonical CBOR\n", deviations);
    return (getenv("STRICT") && deviations) ? 1 : 0;
}
