// CborEngine.cpp
#include "CborEngine.h"

bool CborEncoder::writeUnsignedInt(uint64_t val) {
    if (offset >= capacity) return false;

    if (val < 24) {
        buffer[offset++] = (0 << 5) | val;
    } else if (val <= 0xFF) {
        if (offset + 1 >= capacity) return false;
        buffer[offset++] = (0 << 5) | 24;
        buffer[offset++] = (uint8_t)val;
    } else if (val <= 0xFFFF) {
        if (offset + 2 >= capacity) return false;
        buffer[offset++] = (0 << 5) | 25;
        buffer[offset++] = (val >> 8) & 0xFF;
        buffer[offset++] = val & 0xFF;
    } else if (val <= 0xFFFFFFFF) {
        if (offset + 4 >= capacity) return false;
        buffer[offset++] = (0 << 5) | 26;
        buffer[offset++] = (val >> 24) & 0xFF;
        buffer[offset++] = (val >> 16) & 0xFF;
        buffer[offset++] = (val >> 8) & 0xFF;
        buffer[offset++] = val & 0xFF;
    } else {
        if (offset + 8 >= capacity) return false;
        buffer[offset++] = (0 << 5) | 27;
        buffer[offset++] = (val >> 56) & 0xFF;
        buffer[offset++] = (val >> 48) & 0xFF;
        buffer[offset++] = (val >> 40) & 0xFF;
        buffer[offset++] = (val >> 32) & 0xFF;
        buffer[offset++] = (val >> 24) & 0xFF;
        buffer[offset++] = (val >> 16) & 0xFF;
        buffer[offset++] = (val >> 8) & 0xFF;
        buffer[offset++] = val & 0xFF;
    }
    return true;
}

bool CborEncoder::writeMapHeader(size_t elements) {
    if (offset >= capacity) return false;

    if (elements < 24) {
        buffer[offset++] = (5 << 5) | (elements & 0x1F);
        return true;
    } 
    else if (elements <= 0xFF) {
        if (offset + 1 >= capacity) return false;
        buffer[offset++] = (5 << 5) | 24;
        buffer[offset++] = (uint8_t)elements;
        return true;
    } 
    else if (elements <= 0xFFFF) {
        if (offset + 2 >= capacity) return false;
        buffer[offset++] = (5 << 5) | 25;
        buffer[offset++] = (elements >> 8) & 0xFF;
        buffer[offset++] = elements & 0xFF;
        return true;
    }

    return false;
}

bool CborEncoder::writeByteString(const uint8_t *data, size_t len) {
    if (offset + len + 3 >= capacity) return false;

    if (len < 24) {
        buffer[offset++] = (2 << 5) | (len & 0x1F);
    } 
    else if (len <= 0xFF) {
        buffer[offset++] = (2 << 5) | 24;
        buffer[offset++] = (uint8_t)len;
    } 
    else if (len <= 0xFFFF) {
        buffer[offset++] = (2 << 5) | 25;
        buffer[offset++] = (len >> 8) & 0xFF;
        buffer[offset++] = len & 0xFF;
    } 
    else {
        return false;
    }

    memcpy(&buffer[offset], data, len);
    offset += len;
    return true;
}

bool CborEncoder::writeTextString(const char *text) {
    size_t len = strlen(text);
    if (len > 0xFFFF) return false;
    size_t headerLen = len < 24 ? 1 : (len <= 0xFF ? 2 : 3);
    if (offset + headerLen + len > capacity) return false;

    if (len < 24) {
        buffer[offset++] = (3 << 5) | (len & 0x1F);
    }
    else if (len <= 0xFF) {
        buffer[offset++] = (3 << 5) | 24;
        buffer[offset++] = (uint8_t)len;
    }
    else {
        buffer[offset++] = (3 << 5) | 25;
        buffer[offset++] = (len >> 8) & 0xFF;
        buffer[offset++] = len & 0xFF;
    }

    memcpy(&buffer[offset], text, len);
    offset += len;
    return true;
}

bool CborParser::readTypeAndValue(uint8_t &majorType, uint64_t &value) {
    if (offset >= length) return false;

    size_t start = offset;
    uint8_t initialByte = buffer[offset++];
    majorType = (initialByte >> 5) & 0x07;
    uint8_t additionalInfo = initialByte & 0x1F;
    uint64_t v = 0;

    if (additionalInfo < 24) {
        v = additionalInfo;
    } else if (additionalInfo == 24) {
        if (length - offset < 1) { offset = start; return false; }
        v = buffer[offset++];
        if (v < 24) { offset = start; return false; }
    } else if (additionalInfo == 25) {
        if (length - offset < 2) { offset = start; return false; }
        v = ((uint64_t)buffer[offset] << 8) | buffer[offset + 1];
        offset += 2;
        if (v <= 0xFF) { offset = start; return false; }
    } else if (additionalInfo == 26) {
        if (length - offset < 4) { offset = start; return false; }
        v = ((uint64_t)buffer[offset] << 24) | ((uint64_t)buffer[offset + 1] << 16) |
            ((uint64_t)buffer[offset + 2] << 8) | buffer[offset + 3];
        offset += 4;
        if (v <= 0xFFFF) { offset = start; return false; }
    } else if (additionalInfo == 27) {
        if (length - offset < 8) { offset = start; return false; }
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | buffer[offset++];
        }
        if (v <= 0xFFFFFFFFULL) { offset = start; return false; }
    } else {
        offset = start;
        return false;
    }

    if (majorType == 6) { offset = start; return false; }
    if (majorType == 7 && (additionalInfo < 20 || additionalInfo > 22)) { offset = start; return false; }

    value = v;
    return true;
}

bool CborParser::readByteString(uint8_t *destBuffer, size_t maxLen, size_t &actualLen) {
    uint8_t majorType;
    uint64_t strLen;
    size_t savedOffset = offset;

    if (!readTypeAndValue(majorType, strLen) || majorType != 2) {
        offset = savedOffset;
        return false;
    }

    if (strLen > maxLen || strLen > length - offset) {
        offset = savedOffset;
        return false;
    }

    memcpy(destBuffer, &buffer[offset], strLen);
    actualLen = strLen;
    offset += strLen;
    return true;
}

// NOTE: maxLen is the TOTAL capacity of destBuffer, including room for the
// NUL terminator this function appends. A string of exactly maxLen bytes is
// rejected rather than overflowing the buffer by one byte.
bool CborParser::readTextString(char *destBuffer, size_t maxLen) {
    uint8_t majorType;
    uint64_t strLen;
    size_t savedOffset = offset;

    if (maxLen == 0) return false;

    if (!readTypeAndValue(majorType, strLen) || majorType != 3) {
        offset = savedOffset;
        return false;
    }

    // Reserve one byte for the NUL terminator so destBuffer[strLen] below
    // can never write past the end of the caller's buffer.
    if (strLen > maxLen - 1 || strLen > length - offset) {
        offset = savedOffset;
        return false;
    }

    memcpy(destBuffer, &buffer[offset], strLen);
    destBuffer[strLen] = '\0'; 
    offset += strLen;
    return true;
}

bool CborParser::skipValue(uint8_t depth) {
    if (depth > MAX_CBOR_DEPTH) return false;
    if (offset >= length) return false;

    size_t start = offset;
    uint8_t majorType;
    uint64_t value;
    if (!readTypeAndValue(majorType, value)) return false;

    bool ok = true;
    switch (majorType) {
        case 0:
        case 1:
        case 7:
            break;
        case 2:
        case 3:
            if (value > length - offset) { ok = false; break; }
            offset += (size_t)value;
            break;
        case 4:
            if (value > MAX_CBOR_ELEMENTS) { ok = false; break; }
            for (uint64_t i = 0; ok && i < value; i++) {
                ok = skipValue(depth + 1);
            }
            break;
        case 5:
            if (value > MAX_CBOR_ELEMENTS) { ok = false; break; }
            for (uint64_t i = 0; ok && i < value * 2; i++) {
                ok = skipValue(depth + 1);
            }
            break;
        default:
            ok = false;
            break;
    }

    if (!ok) offset = start;
    return ok;
}

bool CborEncoder::writeArrayHeader(size_t elements) {
    if (offset >= capacity) return false;

    if (elements < 24) {
        buffer[offset++] = (4 << 5) | elements;
        return true;
    } else if (elements <= 0xFF) {
        if (offset + 1 >= capacity) return false;
        buffer[offset++] = (4 << 5) | 24;
        buffer[offset++] = (uint8_t)elements;
        return true;
    } else if (elements <= 0xFFFF) {
        if (offset + 2 >= capacity) return false;
        buffer[offset++] = (4 << 5) | 25;
        buffer[offset++] = (elements >> 8) & 0xFF;
        buffer[offset++] = elements & 0xFF;
        return true;
    }

    return false;
}

bool CborEncoder::writeBoolean(bool value) {
    if (offset >= capacity) return false;

    buffer[offset++] = (7 << 5) | (value ? 21 : 20);
    return true;
}

size_t CborEncoder::getOffset() const {
    return offset;
}

bool CborEncoder::writeNegativeInt(int64_t val) {
    if (val >= 0) return false;

    uint64_t uval = -1 - val;

    if (offset >= capacity) return false;

    if (uval < 24) {
        buffer[offset++] = (1 << 5) | uval;
    } 
    else if (uval <= 0xFF) {
        if (offset + 1 >= capacity) return false; 
        buffer[offset++] = (1 << 5) | 24;
        buffer[offset++] = (uint8_t)uval;
    } 
    else if (uval <= 0xFFFF) {
        if (offset + 2 >= capacity) return false; 
        buffer[offset++] = (1 << 5) | 25;
        buffer[offset++] = (uval >> 8) & 0xFF;
        buffer[offset++] = uval & 0xFF;
    } 
    else if (uval <= 0xFFFFFFFF) {
        if (offset + 4 >= capacity) return false; 
        buffer[offset++] = (1 << 5) | 26;
        buffer[offset++] = (uval >> 24) & 0xFF;
        buffer[offset++] = (uval >> 16) & 0xFF;
        buffer[offset++] = (uval >> 8) & 0xFF;
        buffer[offset++] = uval & 0xFF;
    }
    else {
        if (offset + 8 >= capacity) return false; 
        buffer[offset++] = (1 << 5) | 27;
        buffer[offset++] = (uval >> 56) & 0xFF;
        buffer[offset++] = (uval >> 48) & 0xFF;
        buffer[offset++] = (uval >> 40) & 0xFF;
        buffer[offset++] = (uval >> 32) & 0xFF;
        buffer[offset++] = (uval >> 24) & 0xFF;
        buffer[offset++] = (uval >> 16) & 0xFF;
        buffer[offset++] = (uval >> 8) & 0xFF;
        buffer[offset++] = uval & 0xFF;
    }

    return true;
}

bool CborEncoder::writeNull() {
    if (offset >= capacity) return false;

    buffer[offset++] = (7 << 5) | 22;
    return true;
}