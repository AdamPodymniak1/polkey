CXX      ?= g++
SAN      = -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer
CXXFLAGS = -std=c++17 -g -O1 -Wall -Wextra -Wno-unused-parameter -Wno-attributes -Ishim -I../../include $(SAN)
JSON     = ../../.pio/libdeps/esp32s3/ArduinoJson/src
ASAN_ENV = ASAN_OPTIONS=detect_leaks=0 setarch $(shell uname -m) -R

fuzz: fuzz_cbor
	$(ASAN_ENV) ./fuzz_cbor 2000000 1
	$(ASAN_ENV) ./fuzz_cbor 2000000 2

fuzz_cbor: fuzz_cbor.cpp ../../src/CborEngine.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@

fuzz-libfuzzer: fuzz_cbor.cpp ../../src/CborEngine.cpp
	clang++ -std=c++17 -g -O1 -DLIBFUZZER -fsanitize=fuzzer,address,undefined -Ishim -I../../include $^ -o fuzz_cbor_lf
	@echo "run: ./fuzz_cbor_lf corpus/ -max_len=1024"

test_cbor_strict: test_cbor_strict.cpp ../../src/CborEngine.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@

strict: test_cbor_strict
	$(ASAN_ENV) ./test_cbor_strict

test_ctap_validate: test_ctap_validate.cpp ../../src/CtapValidate.cpp ../../src/CborEngine.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@

validate: test_ctap_validate
	$(ASAN_ENV) ./test_ctap_validate

STORAGE_SRC = test_storage.cpp mocks.cpp ../../src/Globals.cpp
STORAGE_FLAGS = -DARDUINO=10800 -I$(JSON)

test_storage: $(STORAGE_SRC) ../../src/StorageManager.cpp ../../include/StorageManager.h
	$(CXX) $(CXXFLAGS) $(STORAGE_FLAGS) $(STORAGE_SRC) ../../src/StorageManager.cpp -o $@ -lcrypto

storage: test_storage
	$(ASAN_ENV) ./test_storage

legacy/src/StorageManager.cpp:
	mkdir -p legacy/src legacy/include
	git show HEAD:src/StorageManager.cpp > legacy/src/StorageManager.cpp
	git show HEAD:include/StorageManager.h > legacy/include/StorageManager.h

test_storage_legacy: $(STORAGE_SRC) legacy/src/StorageManager.cpp
	$(CXX) -std=c++17 -g -O1 -Wno-attributes -DLEGACY_STORAGE -Ilegacy/include -Ishim -I../../include $(STORAGE_FLAGS) $(STORAGE_SRC) legacy/src/StorageManager.cpp -o $@ -lcrypto

storage-legacy: test_storage_legacy
	./test_storage_legacy

clean:
	rm -rf fuzz_cbor fuzz_cbor_lf test_cbor_strict test_storage test_storage_legacy legacy
