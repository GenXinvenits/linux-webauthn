#ifndef LINUX_WEBAUTHN_CBOR_H
#define LINUX_WEBAUTHN_CBOR_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef enum {
    CBOR_TYPE_UNSIGNED = 0,
    CBOR_TYPE_NEGATIVE,
    CBOR_TYPE_BYTES,
    CBOR_TYPE_TEXT,
    CBOR_TYPE_ARRAY,
    CBOR_TYPE_MAP,
    CBOR_TYPE_BOOL,
    CBOR_TYPE_NULL
} CborType;

typedef struct CborValue CborValue;

struct CborValue {
    CborType type;

    union {
        uint64_t uint_value;
        int64_t int_value;

        struct {
            uint8_t *data;
            size_t length;
        } bytes;

        struct {
            char *data;
            size_t length;
        } text;

        struct {
            CborValue **items;
            size_t count;
        } array;

        struct {
            CborValue **keys;
            CborValue **values;
            size_t count;
        } map;

        bool boolean;
    };
};

/*
 * Create CBOR values.
 */
CborValue *cbor_new_uint(uint64_t value);
CborValue *cbor_new_int(int64_t value);
CborValue *cbor_new_bytes(const uint8_t *data, size_t length);
CborValue *cbor_new_text(const char *text);
CborValue *cbor_new_bool(bool value);
CborValue *cbor_new_null(void);
CborValue *cbor_new_array(void);
CborValue *cbor_new_map(void);

/*
 * Append to arrays and maps.
 *
 * Ownership of the supplied CborValue is transferred to the
 * containing array/map.
 */
int cbor_array_append(
    CborValue *array,
    CborValue *value);

int cbor_map_put(
    CborValue *map,
    CborValue *key,
    CborValue *value);

/*
 * Encode a CBOR value.
 *
 * The returned buffer must be freed with free().
 */
int cbor_encode(
    const CborValue *value,
    uint8_t **data,
    size_t *length);

/*
 * Decode exactly one CBOR value.
 *
 * offset is advanced past the decoded object.
 */
int cbor_decode(
    const uint8_t *data,
    size_t length,
    size_t *offset,
    CborValue **value);

/*
 * Free a complete CBOR value tree.
 */
void cbor_free(
    CborValue *value);

/*
 * Convenience helpers for maps.
 */
CborValue *cbor_map_get_text(
    const CborValue *map,
    const char *key);

CborValue *cbor_map_get_uint(
    const CborValue *map,
    uint64_t key);

/*
 * Type checking helpers.
 */
bool cbor_is_type(
    const CborValue *value,
    CborType type);

#endif
