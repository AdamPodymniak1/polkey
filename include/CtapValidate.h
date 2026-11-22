#ifndef CTAP_VALIDATE_H
#define CTAP_VALIDATE_H

#include <Arduino.h>

uint8_t ctapValidateMakeCredential(const uint8_t *cbor, size_t len);
uint8_t ctapValidateGetAssertion(const uint8_t *cbor, size_t len);

#endif
