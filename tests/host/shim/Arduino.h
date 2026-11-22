#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <memory>
#include <map>

#define PROGMEM
#define PSTR(x) (x)
#define pgm_read_byte(a) (*(const uint8_t *)(a))
#define pgm_read_word(a) (*(const uint16_t *)(a))
#define pgm_read_dword(a) (*(const uint32_t *)(a))
#define pgm_read_float(a) (*(const float *)(a))
#define pgm_read_ptr(a) (*(void *const *)(a))
#define strlen_P strlen
#define strncmp_P strncmp
#define strcmp_P strcmp
#define memcmp_P memcmp
#define memcpy_P memcpy
#define strncpy_P strncpy
class __FlashStringHelper;
#define F(x) (reinterpret_cast<const __FlashStringHelper *>(x))

typedef uint8_t byte;
typedef bool boolean;

class Print;
class Printable {
public:
    virtual ~Printable() {}
    virtual size_t printTo(Print &p) const = 0;
};

class String {
public:
    std::string s;
    String() {}
    String(const char *c) { if (c) s = c; }
    String(const String &o) : s(o.s) {}
    String(char c) { s = std::string(1, c); }
    String(int v) { s = std::to_string(v); }
    String(unsigned v) { s = std::to_string(v); }
    String(long v) { s = std::to_string(v); }
    String(unsigned long v) { s = std::to_string(v); }
    String(long long v) { s = std::to_string(v); }
    String(unsigned long long v) { s = std::to_string(v); }
    String &operator=(const String &o) { s = o.s; return *this; }
    String &operator=(const char *c) { s = c ? c : ""; return *this; }
    const char *c_str() const { return s.c_str(); }
    unsigned int length() const { return (unsigned int)s.size(); }
    char operator[](size_t i) const { return i < s.size() ? s[i] : 0; }
    char charAt(size_t i) const { return (*this)[i]; }
    bool concat(const char *c) { if (c) s += c; return true; }
    bool concat(const char *c, unsigned int n) { s.append(c, n); return true; }
    bool concat(char c) { s += c; return true; }
    bool concat(const String &o) { s += o.s; return true; }
    bool reserve(unsigned int n) { s.reserve(n); return true; }
    String &operator+=(const String &o) { s += o.s; return *this; }
    String &operator+=(const char *c) { if (c) s += c; return *this; }
    String &operator+=(char c) { s += c; return *this; }
    int indexOf(char c, unsigned int from = 0) const {
        if (from > s.size()) return -1;
        size_t p = s.find(c, from);
        return p == std::string::npos ? -1 : (int)p;
    }
    int indexOf(const String &o, unsigned int from = 0) const {
        if (from > s.size()) return -1;
        size_t p = s.find(o.s, from);
        return p == std::string::npos ? -1 : (int)p;
    }
    String substring(unsigned int from) const { return substring(from, (unsigned int)s.size()); }
    String substring(unsigned int from, unsigned int to) const {
        if (from > to) { unsigned int t = from; from = to; to = t; }
        if (from >= s.size()) return String();
        if (to > s.size()) to = (unsigned int)s.size();
        String r; r.s = s.substr(from, to - from); return r;
    }
    long toInt() const { return strtol(s.c_str(), nullptr, 10); }
    bool isEmpty() const { return s.empty(); }
    bool equals(const String &o) const { return s == o.s; }
    bool operator==(const String &o) const { return s == o.s; }
    bool startsWith(const String &p) const { return s.compare(0, p.s.size(), p.s) == 0; }
    bool operator==(const char *c) const { return s == (c ? c : ""); }
    bool operator!=(const String &o) const { return s != o.s; }
    bool operator!=(const char *c) const { return s != (c ? c : ""); }
    bool operator<(const String &o) const { return s < o.s; }
    friend String operator+(const String &a, const String &b) { String r; r.s = a.s + b.s; return r; }
    friend String operator+(const String &a, const char *b) { String r; r.s = a.s + (b ? b : ""); return r; }
    friend String operator+(const char *a, const String &b) { String r; r.s = std::string(a ? a : "") + b.s; return r; }
    friend String operator+(const String &a, char b) { String r; r.s = a.s + b; return r; }
};

class Print {
public:
    virtual ~Print() {}
    virtual size_t write(uint8_t c) = 0;
    virtual size_t write(const uint8_t *b, size_t n) { size_t k = 0; while (k < n && write(b[k])) k++; return k; }
    size_t print(const String &x) { return write((const uint8_t *)x.c_str(), x.length()); }
    size_t print(const char *x) { return write((const uint8_t *)x, strlen(x)); }
    size_t print(int v) { return print(String(v)); }
    size_t print(unsigned v) { return print(String(v)); }
    size_t print(long v) { return print(String(v)); }
    size_t println(const String &x) { return print(x) + print("\n"); }
    size_t println(const char *x) { return print(x) + print("\n"); }
};

class Stream : public Print {
public:
    virtual int available() = 0;
    virtual int read() = 0;
    virtual int peek() = 0;
    size_t readBytes(char *b, size_t n) {
        size_t k = 0;
        while (k < n) { int c = read(); if (c < 0) break; b[k++] = (char)c; }
        return k;
    }
    size_t readBytes(uint8_t *b, size_t n) { return readBytes((char *)b, n); }
    String readString() {
        String r;
        int c;
        while ((c = read()) >= 0) r += (char)c;
        return r;
    }
};

class EspClass {
public:
    void restart();
};
extern EspClass ESP;

unsigned long millis();
void delay(unsigned long ms);
uint32_t esp_random();
void esp_fill_random(void *buf, size_t len);
