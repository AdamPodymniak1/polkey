#pragma once
#include "Arduino.h"

enum SeekMode { SeekSet = 0, SeekCur = 1, SeekEnd = 2 };

struct HostFileState {
    std::string path;
    size_t pos = 0;
    bool writable = false;
    bool valid = false;
};

class File : public Stream {
public:
    std::shared_ptr<HostFileState> st;
    File() {}
    explicit File(std::shared_ptr<HostFileState> s) : st(s) {}
    operator bool() const { return st && st->valid; }
    int available() override;
    int read() override;
    int peek() override;
    size_t read(uint8_t *buf, size_t n);
    size_t write(uint8_t c) override;
    size_t write(const uint8_t *buf, size_t n) override;
    bool seek(uint32_t pos, SeekMode mode = SeekSet);
    size_t position() const;
    size_t size() const;
    void close();
    using Print::write;
};

class SPIFFSFS {
public:
    bool begin(bool format = false);
    bool exists(const char *path);
    File open(const char *path, const char *mode = "r");
    bool remove(const char *path);
    bool rename(const char *from, const char *to);
    size_t totalBytes();
    size_t usedBytes();
};
extern SPIFFSFS SPIFFS;

std::map<std::string, std::vector<uint8_t>> &host_fs();
