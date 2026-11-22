#include "CtapValidate.h"
#include "CborEngine.h"
#include <string.h>

static const uint8_t E_INVALID_PARAMETER = 0x02;
static const uint8_t E_UNEXPECTED_TYPE = 0x11;
static const uint8_t E_INVALID_CBOR = 0x12;
static const uint8_t E_MISSING_PARAMETER = 0x14;
static const uint8_t E_UNSUPPORTED_ALGORITHM = 0x26;
static const uint8_t E_INVALID_OPTION = 0x2C;

static const size_t MAX_USER_ID_LEN = 64;
static const size_t MAX_ENTRIES = 256;

static bool peekHeader(const CborParser &p, uint8_t &type, uint64_t &value) {
    CborParser copy = p;
    return copy.readTypeAndValue(type, value);
}

static bool isBool(uint8_t type, uint64_t value) {
    return type == 7 && (value == 20 || value == 21);
}

static int nextTextKey(CborParser &p, char *buf, size_t cap) {
    uint8_t t;
    uint64_t v;
    if (!peekHeader(p, t, v)) return -1;
    if (t != 3) return 0;
    if (p.readTextString(buf, cap)) return 1;
    buf[0] = 0;
    if (!p.skipValue()) return -1;
    return 2;
}

static uint8_t checkByteString(CborParser &p, uint64_t *lengthOut) {
    uint8_t t;
    uint64_t v;
    if (!peekHeader(p, t, v)) return E_INVALID_CBOR;
    if (t != 2) return E_UNEXPECTED_TYPE;
    if (lengthOut) *lengthOut = v;
    if (!p.skipValue()) return E_INVALID_CBOR;
    return 0;
}

static uint8_t checkTextString(CborParser &p, char *buf, size_t cap) {
    uint8_t t;
    uint64_t v;
    if (!peekHeader(p, t, v)) return E_INVALID_CBOR;
    if (t != 3) return E_UNEXPECTED_TYPE;
    if (buf != nullptr && cap > 0 && p.readTextString(buf, cap)) return 0;
    if (buf != nullptr && cap > 0) buf[0] = 0;
    if (!p.skipValue()) return E_INVALID_CBOR;
    return 0;
}

static uint8_t openContainer(CborParser &p, uint8_t expectedType, uint64_t &count) {
    uint8_t t;
    if (!peekHeader(p, t, count)) return E_INVALID_CBOR;
    if (t != expectedType) return E_UNEXPECTED_TYPE;
    if (count > MAX_ENTRIES) return E_INVALID_CBOR;
    if (!p.readTypeAndValue(t, count)) return E_INVALID_CBOR;
    return 0;
}

static uint8_t checkEntity(CborParser &p, bool isUser) {
    uint64_t count;
    uint8_t err = openContainer(p, 5, count);
    if (err) return err;
    bool haveId = false;
    for (uint64_t i = 0; i < count; i++) {
        char key[24];
        int k = nextTextKey(p, key, sizeof(key));
        if (k < 0) return E_INVALID_CBOR;
        if (k == 0) return E_UNEXPECTED_TYPE;
        if (k == 1 && strcmp(key, "id") == 0) {
            if (isUser) {
                uint64_t idLen = 0;
                err = checkByteString(p, &idLen);
                if (err) return err;
                if (idLen > MAX_USER_ID_LEN) return E_INVALID_PARAMETER;
            } else {
                err = checkTextString(p, nullptr, 0);
                if (err) return err;
            }
            haveId = true;
        } else if (k == 1 && (strcmp(key, "name") == 0 || strcmp(key, "icon") == 0 ||
                              (isUser && strcmp(key, "displayName") == 0))) {
            err = checkTextString(p, nullptr, 0);
            if (err) return err;
        } else {
            if (!p.skipValue()) return E_INVALID_CBOR;
        }
    }
    return haveId ? 0 : E_MISSING_PARAMETER;
}

static bool isSupportedAlgorithm(int64_t alg) {
    return alg == -7 || alg == -8 || alg == -257 || alg == -48 || alg == -49 || alg == -50;
}

static uint8_t checkCredParams(CborParser &p) {
    uint64_t count;
    uint8_t err = openContainer(p, 4, count);
    if (err) return err;
    bool anySupported = false;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t fields;
        err = openContainer(p, 5, fields);
        if (err) return err;
        bool haveType = false, haveAlg = false;
        bool typeIsPublicKey = false;
        int64_t alg = 0;
        for (uint64_t j = 0; j < fields; j++) {
            char key[16];
            int k = nextTextKey(p, key, sizeof(key));
            if (k < 0) return E_INVALID_CBOR;
            if (k == 0) return E_UNEXPECTED_TYPE;
            if (k == 1 && strcmp(key, "type") == 0) {
                char typeBuf[16];
                err = checkTextString(p, typeBuf, sizeof(typeBuf));
                if (err) return err;
                typeIsPublicKey = strcmp(typeBuf, "public-key") == 0;
                haveType = true;
            } else if (k == 1 && strcmp(key, "alg") == 0) {
                uint8_t t;
                uint64_t v;
                if (!peekHeader(p, t, v)) return E_INVALID_CBOR;
                if (t != 0 && t != 1) return E_UNEXPECTED_TYPE;
                if (v > 0x7FFFFFFF) {
                    alg = 0;
                } else {
                    alg = (t == 0) ? (int64_t)v : -1 - (int64_t)v;
                }
                if (!p.skipValue()) return E_INVALID_CBOR;
                haveAlg = true;
            } else {
                if (!p.skipValue()) return E_INVALID_CBOR;
            }
        }
        if (!haveType) return E_MISSING_PARAMETER;
        if (!haveAlg) return E_MISSING_PARAMETER;
        if (typeIsPublicKey && isSupportedAlgorithm(alg)) anySupported = true;
    }
    return anySupported ? 0 : E_UNSUPPORTED_ALGORITHM;
}

static uint8_t checkDescriptorList(CborParser &p) {
    uint64_t count;
    uint8_t err = openContainer(p, 4, count);
    if (err) return err;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t fields;
        err = openContainer(p, 5, fields);
        if (err) return err;
        bool haveType = false, haveId = false;
        for (uint64_t j = 0; j < fields; j++) {
            char key[16];
            int k = nextTextKey(p, key, sizeof(key));
            if (k < 0) return E_INVALID_CBOR;
            if (k == 0) return E_UNEXPECTED_TYPE;
            if (k == 1 && strcmp(key, "type") == 0) {
                err = checkTextString(p, nullptr, 0);
                if (err) return err;
                haveType = true;
            } else if (k == 1 && strcmp(key, "id") == 0) {
                err = checkByteString(p, nullptr);
                if (err) return err;
                haveId = true;
            } else {
                if (!p.skipValue()) return E_INVALID_CBOR;
            }
        }
        if (!haveType || !haveId) return E_MISSING_PARAMETER;
    }
    return 0;
}

static uint8_t checkMapSkipping(CborParser &p) {
    uint8_t t;
    uint64_t v;
    if (!peekHeader(p, t, v)) return E_INVALID_CBOR;
    if (t != 5) return E_UNEXPECTED_TYPE;
    if (!p.skipValue()) return E_INVALID_CBOR;
    return 0;
}

static uint8_t checkOptions(CborParser &p, bool rejectUp) {
    uint64_t count;
    uint8_t err = openContainer(p, 5, count);
    if (err) return err;
    for (uint64_t i = 0; i < count; i++) {
        char key[16];
        int k = nextTextKey(p, key, sizeof(key));
        if (k < 0) return E_INVALID_CBOR;
        if (k == 0) return E_UNEXPECTED_TYPE;
        if (k == 1 && (strcmp(key, "rk") == 0 || strcmp(key, "up") == 0 || strcmp(key, "uv") == 0)) {
            uint8_t t;
            uint64_t v;
            if (!peekHeader(p, t, v)) return E_INVALID_CBOR;
            if (!isBool(t, v)) return E_UNEXPECTED_TYPE;
            if (rejectUp && strcmp(key, "up") == 0) return E_INVALID_OPTION;
        }
        if (!p.skipValue()) return E_INVALID_CBOR;
    }
    return 0;
}

static uint8_t checkClientDataHash(CborParser &p) {
    uint64_t len = 0;
    uint8_t err = checkByteString(p, &len);
    if (err) return err;
    return len == 32 ? 0 : E_INVALID_PARAMETER;
}

static uint8_t checkUnsigned(CborParser &p) {
    uint8_t t;
    uint64_t v;
    if (!peekHeader(p, t, v)) return E_INVALID_CBOR;
    if (t != 0) return E_UNEXPECTED_TYPE;
    if (!p.skipValue()) return E_INVALID_CBOR;
    return 0;
}

uint8_t ctapValidateMakeCredential(const uint8_t *cbor, size_t len) {
    if (len == 0) return E_MISSING_PARAMETER;
    CborParser p(cbor, len);
    uint64_t count;
    uint8_t err = openContainer(p, 5, count);
    if (err) return err;

    bool haveCdh = false, haveRp = false, haveUser = false, haveParams = false;
    for (uint64_t i = 0; i < count; i++) {
        uint8_t kt;
        uint64_t key;
        if (!peekHeader(p, kt, key)) return E_INVALID_CBOR;
        if (kt != 0) return E_UNEXPECTED_TYPE;
        p.readTypeAndValue(kt, key);
        switch (key) {
            case 1: err = checkClientDataHash(p); haveCdh = true; break;
            case 2: err = checkEntity(p, false); haveRp = true; break;
            case 3: err = checkEntity(p, true); haveUser = true; break;
            case 4: err = checkCredParams(p); haveParams = true; break;
            case 5: err = checkDescriptorList(p); break;
            case 6: err = checkMapSkipping(p); break;
            case 7: err = checkOptions(p, true); break;
            case 8: err = checkByteString(p, nullptr); break;
            case 9: err = checkUnsigned(p); break;
            default: err = p.skipValue() ? 0 : E_INVALID_CBOR; break;
        }
        if (err) return err;
    }
    if (!p.isFinished()) return E_INVALID_CBOR;
    if (!haveCdh || !haveRp || !haveUser || !haveParams) return E_MISSING_PARAMETER;
    return 0;
}

uint8_t ctapValidateGetAssertion(const uint8_t *cbor, size_t len) {
    if (len == 0) return E_MISSING_PARAMETER;
    CborParser p(cbor, len);
    uint64_t count;
    uint8_t err = openContainer(p, 5, count);
    if (err) return err;

    bool haveRp = false, haveCdh = false;
    for (uint64_t i = 0; i < count; i++) {
        uint8_t kt;
        uint64_t key;
        if (!peekHeader(p, kt, key)) return E_INVALID_CBOR;
        if (kt != 0) return E_UNEXPECTED_TYPE;
        p.readTypeAndValue(kt, key);
        switch (key) {
            case 1: err = checkTextString(p, nullptr, 0); haveRp = true; break;
            case 2: err = checkClientDataHash(p); haveCdh = true; break;
            case 3: err = checkDescriptorList(p); break;
            case 4: err = checkMapSkipping(p); break;
            case 5: err = checkOptions(p, false); break;
            case 6: err = checkByteString(p, nullptr); break;
            case 7: err = checkUnsigned(p); break;
            default: err = p.skipValue() ? 0 : E_INVALID_CBOR; break;
        }
        if (err) return err;
    }
    if (!p.isFinished()) return E_INVALID_CBOR;
    if (!haveRp || !haveCdh) return E_MISSING_PARAMETER;
    return 0;
}
