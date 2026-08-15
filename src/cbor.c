#include "cbor.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t *data;
    size_t length;
    size_t capacity;
} CborBuffer;

static int buffer_reserve(
    CborBuffer *buffer,
    size_t additional)
{
    size_t required;
    size_t capacity;
    uint8_t *new_data;

    if (!buffer)
        return -1;

    if (additional > SIZE_MAX - buffer->length)
        return -1;

    required = buffer->length + additional;

    if (required <= buffer->capacity)
        return 0;

    capacity = buffer->capacity ? buffer->capacity : 256;

    while (capacity < required) {
        if (capacity > SIZE_MAX / 2)
            return -1;

        capacity *= 2;
    }

    new_data = realloc(buffer->data, capacity);
    if (!new_data)
        return -1;

    buffer->data = new_data;
    buffer->capacity = capacity;

    return 0;
}

static int buffer_put(
    CborBuffer *buffer,
    const void *data,
    size_t length)
{
    if (buffer_reserve(buffer, length) != 0)
        return -1;

    if (length > 0)
        memcpy(buffer->data + buffer->length, data, length);

    buffer->length += length;

    return 0;
}

static int buffer_put_byte(
    CborBuffer *buffer,
    uint8_t byte)
{
    return buffer_put(buffer, &byte, 1);
}

static CborValue *value_alloc(CborType type)
{
    CborValue *value;

    value = calloc(1, sizeof(*value));
    if (!value)
        return NULL;

    value->type = type;

    return value;
}

CborValue *cbor_new_uint(uint64_t value)
{
    CborValue *result = value_alloc(CBOR_TYPE_UNSIGNED);

    if (result)
        result->uint_value = value;

    return result;
}

CborValue *cbor_new_int(int64_t value)
{
    CborValue *result;

    if (value >= 0)
        return cbor_new_uint((uint64_t)value);

    result = value_alloc(CBOR_TYPE_NEGATIVE);

    if (result)
        result->int_value = value;

    return result;
}

CborValue *cbor_new_bytes(
    const uint8_t *data,
    size_t length)
{
    CborValue *result;

    if (length > 0 && !data)
        return NULL;

    result = value_alloc(CBOR_TYPE_BYTES);
    if (!result)
        return NULL;

    if (length > 0) {
        result->bytes.data = malloc(length);

        if (!result->bytes.data) {
            free(result);
            return NULL;
        }

        memcpy(result->bytes.data, data, length);
    }

    result->bytes.length = length;

    return result;
}

CborValue *cbor_new_text(const char *text)
{
    CborValue *result;
    size_t length;

    if (!text)
        return NULL;

    length = strlen(text);

    result = value_alloc(CBOR_TYPE_TEXT);
    if (!result)
        return NULL;

    result->text.data = malloc(length + 1);

    if (!result->text.data) {
        free(result);
        return NULL;
    }

    memcpy(result->text.data, text, length + 1);
    result->text.length = length;

    return result;
}

CborValue *cbor_new_bool(bool value)
{
    CborValue *result = value_alloc(CBOR_TYPE_BOOL);

    if (result)
        result->boolean = value;

    return result;
}

CborValue *cbor_new_null(void)
{
    return value_alloc(CBOR_TYPE_NULL);
}

CborValue *cbor_new_array(void)
{
    return value_alloc(CBOR_TYPE_ARRAY);
}

CborValue *cbor_new_map(void)
{
    return value_alloc(CBOR_TYPE_MAP);
}

int cbor_array_append(
    CborValue *array,
    CborValue *value)
{
    CborValue **items;

    if (!array ||
        array->type != CBOR_TYPE_ARRAY ||
        !value)
        return -1;

    if (array->array.count == SIZE_MAX / sizeof(*items))
        return -1;

    items = realloc(
        array->array.items,
        (array->array.count + 1) * sizeof(*items));

    if (!items)
        return -1;

    array->array.items = items;
    array->array.items[array->array.count] = value;
    array->array.count++;

    return 0;
}

int cbor_map_put(
    CborValue *map,
    CborValue *key,
    CborValue *value)
{
    CborValue **keys;
    CborValue **values;
    size_t count;

    if (!map ||
        map->type != CBOR_TYPE_MAP ||
        !key ||
        !value)
        return -1;

    count = map->map.count;

    if (count == SIZE_MAX / sizeof(*keys))
        return -1;

    keys = realloc(
        map->map.keys,
        (count + 1) * sizeof(*keys));

    if (!keys)
        return -1;

    values = realloc(
        map->map.values,
        (count + 1) * sizeof(*values));

    if (!values) {
        map->map.keys = keys;
        return -1;
    }

    map->map.keys = keys;
    map->map.values = values;

    map->map.keys[count] = key;
    map->map.values[count] = value;
    map->map.count++;

    return 0;
}

static int encode_type_length(
    CborBuffer *buffer,
    uint8_t major,
    uint64_t value)
{
    uint8_t byte;

    if (value < 24) {
        byte = (uint8_t)((major << 5) | value);
        return buffer_put_byte(buffer, byte);
    }

    if (value <= UINT8_MAX) {
        byte = (uint8_t)((major << 5) | 24);

        if (buffer_put_byte(buffer, byte) != 0)
            return -1;

        byte = (uint8_t)value;

        return buffer_put_byte(buffer, byte);
    }

    if (value <= UINT16_MAX) {
        uint8_t bytes[2];

        byte = (uint8_t)((major << 5) | 25);

        bytes[0] = (uint8_t)(value >> 8);
        bytes[1] = (uint8_t)value;

        if (buffer_put_byte(buffer, byte) != 0)
            return -1;

        return buffer_put(buffer, bytes, sizeof(bytes));
    }

    if (value <= UINT32_MAX) {
        uint8_t bytes[4];

        byte = (uint8_t)((major << 5) | 26);

        bytes[0] = (uint8_t)(value >> 24);
        bytes[1] = (uint8_t)(value >> 16);
        bytes[2] = (uint8_t)(value >> 8);
        bytes[3] = (uint8_t)value;

        if (buffer_put_byte(buffer, byte) != 0)
            return -1;

        return buffer_put(buffer, bytes, sizeof(bytes));
    }

    {
        uint8_t bytes[8];

        byte = (uint8_t)((major << 5) | 27);

        bytes[0] = (uint8_t)(value >> 56);
        bytes[1] = (uint8_t)(value >> 48);
        bytes[2] = (uint8_t)(value >> 40);
        bytes[3] = (uint8_t)(value >> 32);
        bytes[4] = (uint8_t)(value >> 24);
        bytes[5] = (uint8_t)(value >> 16);
        bytes[6] = (uint8_t)(value >> 8);
        bytes[7] = (uint8_t)value;

        if (buffer_put_byte(buffer, byte) != 0)
            return -1;

        return buffer_put(buffer, bytes, sizeof(bytes));
    }
}

static int encode_value(
    const CborValue *value,
    CborBuffer *buffer)
{
    size_t i;

    if (!value || !buffer)
        return -1;

    switch (value->type) {
    case CBOR_TYPE_UNSIGNED:
        return encode_type_length(
            buffer,
            0,
            value->uint_value);

    case CBOR_TYPE_NEGATIVE: {
        uint64_t encoded;

        /*
         * CBOR negative integer representation:
         *
         *   -1 -> 0
         *   -2 -> 1
         */
        if (value->int_value >= 0)
            return -1;

        encoded = (uint64_t)(-(value->int_value + 1));

        return encode_type_length(
            buffer,
            1,
            encoded);
    }

    case CBOR_TYPE_BYTES:
        if (encode_type_length(
                buffer,
                2,
                value->bytes.length) != 0)
            return -1;

        return buffer_put(
            buffer,
            value->bytes.data,
            value->bytes.length);

    case CBOR_TYPE_TEXT:
        if (encode_type_length(
                buffer,
                3,
                value->text.length) != 0)
            return -1;

        return buffer_put(
            buffer,
            value->text.data,
            value->text.length);

    case CBOR_TYPE_ARRAY:
        if (encode_type_length(
                buffer,
                4,
                value->array.count) != 0)
            return -1;

        for (i = 0; i < value->array.count; i++) {
            if (encode_value(
                    value->array.items[i],
                    buffer) != 0)
                return -1;
        }

        return 0;

    case CBOR_TYPE_MAP:
        if (encode_type_length(
                buffer,
                5,
                value->map.count) != 0)
            return -1;

        for (i = 0; i < value->map.count; i++) {
            if (encode_value(
                    value->map.keys[i],
                    buffer) != 0)
                return -1;

            if (encode_value(
                    value->map.values[i],
                    buffer) != 0)
                return -1;
        }

        return 0;

    case CBOR_TYPE_BOOL:
        return buffer_put_byte(
            buffer,
            value->boolean ? 0xF5 : 0xF4);

    case CBOR_TYPE_NULL:
        return buffer_put_byte(buffer, 0xF6);
    }

    return -1;
}

int cbor_encode(
    const CborValue *value,
    uint8_t **data,
    size_t *length)
{
    CborBuffer buffer = { 0 };

    if (!value || !data || !length)
        return -1;

    *data = NULL;
    *length = 0;

    if (encode_value(value, &buffer) != 0) {
        free(buffer.data);
        return -1;
    }

    *data = buffer.data;
    *length = buffer.length;

    return 0;
}

static int read_byte(
    const uint8_t *data,
    size_t length,
    size_t *offset,
    uint8_t *result)
{
    if (!data ||
        !offset ||
        !result ||
        *offset >= length)
        return -1;

    *result = data[*offset];
    (*offset)++;

    return 0;
}

static int read_uint(
    const uint8_t *data,
    size_t length,
    size_t *offset,
    uint8_t additional,
    uint64_t *result)
{
    uint8_t bytes[8];
    size_t count;
    size_t i;

    if (!result)
        return -1;

    if (additional < 24) {
        *result = additional;
        return 0;
    }

    switch (additional) {
    case 24:
        count = 1;
        break;

    case 25:
        count = 2;
        break;

    case 26:
        count = 4;
        break;

    case 27:
        count = 8;
        break;

    default:
        return -1;
    }

    if (!data ||
        !offset ||
        count > length - *offset)
        return -1;

    memcpy(bytes, data + *offset, count);
    *offset += count;

    *result = 0;

    for (i = 0; i < count; i++)
        *result = (*result << 8) | bytes[i];

    return 0;
}

static int decode_value_internal(
    const uint8_t *data,
    size_t length,
    size_t *offset,
    CborValue **value,
    unsigned depth)
{
    uint8_t initial;
    uint8_t major;
    uint8_t additional;
    uint64_t argument;
    CborValue *result;
    size_t i;

    if (!data ||
        !offset ||
        !value ||
        depth > 64)
        return -1;

    *value = NULL;

    if (read_byte(
            data,
            length,
            offset,
            &initial) != 0)
        return -1;

    major = initial >> 5;
    additional = initial & 0x1F;

    if (additional == 31)
        return -1;

    if (major <= 5) {
        if (read_uint(
                data,
                length,
                offset,
                additional,
                &argument) != 0)
            return -1;
    }

    switch (major) {
    case 0:
        result = cbor_new_uint(argument);
        break;

    case 1:
        if (argument > (uint64_t)INT64_MAX)
            return -1;

        result = cbor_new_int(
            -(int64_t)(argument + 1));
        break;

    case 2:
        if (argument > SIZE_MAX ||
            argument > length - *offset)
            return -1;

        result = cbor_new_bytes(
            data + *offset,
            (size_t)argument);

        *offset += (size_t)argument;
        break;

    case 3:
        if (argument > SIZE_MAX ||
            argument > length - *offset)
            return -1;

        if (argument == SIZE_MAX)
            return -1;

        result = value_alloc(CBOR_TYPE_TEXT);

        if (result) {
            result->text.data = malloc((size_t)argument + 1);

            if (!result->text.data) {
                free(result);
                return -1;
            }

            memcpy(
                result->text.data,
                data + *offset,
                (size_t)argument);

            result->text.data[argument] = '\0';
            result->text.length = (size_t)argument;

            *offset += (size_t)argument;
        }

        break;

    case 4:
        if (argument > SIZE_MAX)
            return -1;

        result = cbor_new_array();

        if (!result)
            return -1;

        for (i = 0; i < (size_t)argument; i++) {
            CborValue *item = NULL;

            if (decode_value_internal(
                    data,
                    length,
                    offset,
                    &item,
                    depth + 1) != 0 ||
                cbor_array_append(result, item) != 0) {
                cbor_free(item);
                cbor_free(result);
                return -1;
            }
        }

        break;

    case 5:
        if (argument > SIZE_MAX)
            return -1;

        result = cbor_new_map();

        if (!result)
            return -1;

        for (i = 0; i < (size_t)argument; i++) {
            CborValue *key = NULL;
            CborValue *map_value = NULL;

            if (decode_value_internal(
                    data,
                    length,
                    offset,
                    &key,
                    depth + 1) != 0 ||
                decode_value_internal(
                    data,
                    length,
                    offset,
                    &map_value,
                    depth + 1) != 0 ||
                cbor_map_put(
                    result,
                    key,
                    map_value) != 0) {
                cbor_free(key);
                cbor_free(map_value);
                cbor_free(result);
                return -1;
            }
        }

        break;

    case 6:
        /*
         * CTAP2 does not require CBOR tags for the initial
         * implementation. Reject them rather than silently
         * interpreting tagged data.
         */
        return -1;

    case 7:
        if (additional == 20)
            result = cbor_new_bool(false);
        else if (additional == 21)
            result = cbor_new_bool(true);
        else if (additional == 22)
            result = cbor_new_null();
        else
            return -1;

        break;

    default:
        return -1;
    }

    if (!result)
        return -1;

    *value = result;

    return 0;
}

int cbor_decode(
    const uint8_t *data,
    size_t length,
    size_t *offset,
    CborValue **value)
{
    return decode_value_internal(
        data,
        length,
        offset,
        value,
        0);
}

void cbor_free(CborValue *value)
{
    size_t i;

    if (!value)
        return;

    switch (value->type) {
    case CBOR_TYPE_BYTES:
        free(value->bytes.data);
        break;

    case CBOR_TYPE_TEXT:
        free(value->text.data);
        break;

    case CBOR_TYPE_ARRAY:
        for (i = 0; i < value->array.count; i++)
            cbor_free(value->array.items[i]);

        free(value->array.items);
        break;

    case CBOR_TYPE_MAP:
        for (i = 0; i < value->map.count; i++) {
            cbor_free(value->map.keys[i]);
            cbor_free(value->map.values[i]);
        }

        free(value->map.keys);
        free(value->map.values);
        break;

    default:
        break;
    }

    free(value);
}

bool cbor_is_type(
    const CborValue *value,
    CborType type)
{
    return value && value->type == type;
}

CborValue *cbor_map_get_text(
    const CborValue *map,
    const char *key)
{
    size_t i;

    if (!map ||
        map->type != CBOR_TYPE_MAP ||
        !key)
        return NULL;

    for (i = 0; i < map->map.count; i++) {
        CborValue *map_key = map->map.keys[i];

        if (!map_key ||
            map_key->type != CBOR_TYPE_TEXT)
            continue;

        if (strcmp(map_key->text.data, key) == 0)
            return map->map.values[i];
    }

    return NULL;
}

CborValue *cbor_map_get_uint(
    const CborValue *map,
    uint64_t key)
{
    size_t i;

    if (!map || map->type != CBOR_TYPE_MAP)
        return NULL;

    for (i = 0; i < map->map.count; i++) {
        CborValue *map_key = map->map.keys[i];

        if (!map_key ||
            map_key->type != CBOR_TYPE_UNSIGNED)
            continue;

        if (map_key->uint_value == key)
            return map->map.values[i];
    }

    return NULL;
}