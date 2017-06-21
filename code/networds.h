/***

todo
[ ] : to start  [x] : complete  [i] : in progress  [w] : won't do

[i] Write command line loop.
[i] Write more unit tests for strpool.
[ ] Make right use of size_t.
[ ] Validate command line arguments for alphabet-only strings.
[ ] Address reference counting issue of strpool_handle.
[ ] Add memory footprint metrics.
[x] Fix lt_str_ncompare.
[x] Handle memory allocation of netword_t and networdpool_t.
[x] Make a simple stupid unit test framework that can save me from manually 
    calling every test function.
[x] Revise strpool_string_node structure and the way of finding next free node.
[x] Parse JSON to netword structs in memory.
[x] Finish strpool_discard_handle function, take into account of ref_count.
[x] Fix all lt_* functions.
[x] Upload this project to Github.

***/


#pragma once

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h> // memcmp, memcpy
#include <time.h>

/*========================
    Helper Functions
========================*/

/**
 * Compute the smallest power of 2 that's larger than or equal to x.
 * reference: https://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
 */
uint32_t next_pow2(uint32_t x)
{
    assert(x < 0x80000001);
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    x++;
    x += (x == 0);
    return x;
}

/**
 * @param a The alignment must be power of 2
 */
uint32_t memory_align(uint32_t memory, uint32_t a)
{
	assert(a > 0);
    uint32_t result = (memory + a - 1) & (~(a - 1));
    return result;
}

/*==============================
    String Operations 
==============================*/

/**
 * @param str The input string has to be null-terminated.
 * @return The length of the input string , not including '\0'.
 */
int lt_str_length(const char *str)
{
    int length = 0;
    while (*(str + length) != '\0')
    {
        length++;
    }
    return length;
}

/**
 * Copy the string from the source buffer to the destination buffer. If the '\0' 
 * is met before the specified number of characters is copied, terminate the
 * copying process and append '\0' to the destination buffer.
 *
 * @param dest The destination buffer to store copied string.
 * @param dest_size The number of characters the destination buffer can hold.
 * @param src The source buffer to copy the string from.
 * @param src_size The number of character to copy from the source buffer.
 * @return The number of characters copied, excluding '\0'. 
 */
int lt_str_ncopy(char *dest, int dest_size, const char *src, int src_size = 0)
{
    int dest_pos = 0;
    int dest_end = dest_size - 1;
    int src_pos = 0;

    if (src_size == 0)
    {
        src_size = lt_str_length(src);
    }

    while (*(src + src_pos) != '\0' && 
            src_pos < src_size &&
            dest_pos < dest_end)
    {
        *(dest + dest_pos) = *(src + src_pos);
        src_pos++;
        dest_pos++;
    }
    *(dest + dest_pos) = '\0';

    return dest_pos;
}

/**
 * Compare \ref count characters from two null-terminated strings. Return the 
 * difference of two characters from each string as soon as they differ, 
 * otherwise return 0. The default \ref count is 0 in which case two strings 
 * have to have the same length to be considered equal.
 *
 * Examples: ("aabb", "aabbc", 4) returns 0
 *           ("aabb", "aabbc", 5) returns negative integer
 *           ("aAbb", "aabb", 4) returns negative integer
 */
int lt_str_ncompare(const char * __restrict str0, const char * __restrict str1, size_t count)
{
    while (count > 0)
    {
        if (*str0 != *str1)
        {
            return *str0 - *str1;
        }

        str0++;
        str1++;
        count--;
    }
    return 0;
}

/**
 *
 */
int lt_str_concat(const char * __restrict str0, size_t str0_size,
                  const char * __restrict str1, size_t str1_size, 
                  char * __restrict dest_buffer, size_t dest_buffer_size)
{
    size_t pos0 = 0;
    size_t pos1 = 0;
    size_t dest_pos = 0;
    while (pos0 < str0_size)
    {
        if (dest_pos >= dest_buffer_size - 1)
        {
            dest_buffer[dest_pos] = '\0';
            return 1;
        }
        dest_buffer[dest_pos++] = str0[pos0++];
    }

    while (pos1 < str1_size)
    {
        if (dest_pos >= dest_buffer_size - 1)
        {
            dest_buffer[dest_pos] = '\0';
            return 2;
        }
        dest_buffer[dest_pos++] = str1[pos1++];
    }

    dest_buffer[dest_pos] = '\0';

    return 0;
}


/*================
    String Pool 
================*/

#define STRPOOL_MALLOC_SENTINEL 0x771df001

void *strpool_malloc(size_t size)
{
    char *mem = (char *)malloc(size + sizeof(size_t) + sizeof(int32_t));
    *(size_t *)mem = size;
    char *result = mem + sizeof(size_t);
    *(uint32_t *)(result + size) = STRPOOL_MALLOC_SENTINEL;
    return (void *)result;
}

void strpool_free(void *ptr)
{
    char *real_ptr = (char *)ptr - sizeof(size_t);
    size_t size = *(size_t *)real_ptr;
    uint32_t sentinel = *(uint32_t *)(real_ptr + sizeof(size_t) + size);
    // I believe crt's free() already does something like this. But I don't have
    // source code and can't debug it. We have to do it again ourselves.
    assert(sentinel == STRPOOL_MALLOC_SENTINEL);
    free(real_ptr);
}

struct strpool_hashslot
{
    uint32_t string_hash;
    int32_t entry_index;
    // the number of times a string is originally hashed at this slot
    int32_t base_count;
};

/**
 * String entry
 */
struct strpool_entry
{
    uint32_t string_hash;

    union
    {
        // memory offset of the actual string data in strpool.string_block, not 
        // including the strpool_string_node
        int32_t string_data_offset;
        // used when the entry is free
        int32_t prev_free_entry_index;
    };
    union
    {
        int32_t hashslot;
        // used when the entry is free
        int32_t next_free_entry_index;
    };

    // this is a free entry if ref_count is 0
    uint32_t ref_count;
};

struct strpool_handle
{
    int32_t entry_index;

    strpool_handle()
        : entry_index(0)
    { }

    strpool_handle(int32_t entry_index_)
        : entry_index(entry_index_)
    { }

    bool operator==(const strpool_handle other)
    {
        return entry_index == other.entry_index;
    }

    bool operator!=(const strpool_handle other)
    {
        return entry_index != other.entry_index;
    }
};

/**
 * A strpool_string_node is stored in front of every string in memory. It's used 
 * to create a special doubly linked list of which the order of the nodes is the
 * same as they are stored in memory. For example if node_a->front_node_offset 
 * == node_b_offset, then node_b_offset + node_b->size == node_a_offset. This 
 * imposition is to save memory which otherwise would include two extra int32 
 * for prev_node_offset and next_node_offset. Even then front_node_offset has to
 * exist to help merge a node, when it's being freed, with a possible free node 
 * directly in front of it in memory. This makes searching free node for 
 * insertion O(n) instead O(1) because now we can't chain all free nodes in 
 * front of the list but need to loop through all nodes, which isn't too bad 
 * considering our usage pattern in this program.
 */
struct strpool_string_node
{
    // the memory offset of the string node that's physically in front of this 
    // node in memory
    int32_t front_node_offset;
    // size = sizeof(strpool_string_node) + string_length + sizeof('\0') + alignment_padding
    int32_t size; 
    // string_length == 0 means it's a free node
    int32_t string_length;
};

static const int32_t STRPOOL_STRING_BLOCK_MIN_SIZE = (int32_t)(sizeof(strpool_string_node) * 2);
static const int32_t STRPOOL_DUMMY_NODE_LENGTH_SENTINEL = 1771;
static const int32_t STRPOOL_DUMMY_NODE_SIZE = (int32_t)sizeof(strpool_string_node);

struct strpool
{
    strpool_hashslot *hashslots = 0;
    strpool_entry *entries = 0;

    // Memory block storing all strings. Each string must be appended with '\0', 
    // and prepended with a strpool_string_node.
    char *string_block = 0;
    int32_t string_block_size = 0;

    // dummy node serves as head and tail for a circular linked list
    int32_t dummy_node_offset = 0;
    int32_t first_free_node_offset = 0;

    // dummy free entry, always 0
    int32_t dummy_free_entry_index = 0;

    int32_t hashslot_capacity = 0;
    // int32_t hashslot_count = 0; this should always equal entry_count
    int32_t entry_capacity = 0;
    int32_t entry_count = 0;
    int32_t free_entry_list_count = 0;

    // load_factor = 1 - 1/load_divider
    int32_t hashslots_load_divider = 3;

    ~strpool()
    {
        if (hashslots != 0)
        {
            strpool_free(hashslots);
        }

        if (entries != 0)
        {
			strpool_free(entries);
        }

        if (string_block != 0)
        {
			strpool_free(string_block);
        }
    }
};

uint32_t strpool_calculate_string_hash(const char *string, int32_t length)
{
    uint32_t hash = 5381U;

    for (int i = 0; i < length; ++i)
    {
        char c = string[i];
        hash = ((hash << 5U) + hash) ^ c;
    }

    hash = (hash == 0) ? 1 : hash; // We can't allow 0-value hash keys, but duplicates are ok
    return hash;
}

#define STRPOOL_STRING_HASH_F(name) uint32_t name(const char *string, int32_t length)
typedef STRPOOL_STRING_HASH_F(strpool_string_hash_f);
strpool_string_hash_f *strpool_calc_string_hash = strpool_calculate_string_hash;

inline strpool_string_node *strpool_get_string_node(strpool *pool, int32_t offset)
{
    strpool_string_node *result = (strpool_string_node *)(pool->string_block + offset);
    return result;
}

/** 
 * Put dummy at the end of the memory and set the size to -dummy_node_offset
 * so that when we loop through the dummy node we can go back to the first
 * node with the same calculation which is next_node_offset =
 * dummy_node_offset + dummy_node->size.
 */
void strpool_extend_string_block(strpool *pool, int32_t new_string_block_size)
{
	assert(new_string_block_size > pool->string_block_size);
    char *new_string_block = (char *)strpool_malloc(new_string_block_size);
    assert(new_string_block);

    int32_t first_free_node_offset = 0;
    strpool_string_node *first_free_node = 0;

    if (pool->string_block != 0)
    {
        memcpy(new_string_block, pool->string_block, pool->string_block_size);
        memset(new_string_block + pool->string_block_size, 0, new_string_block_size - pool->string_block_size);

		char *old_string_block = pool->string_block;
		int32_t old_string_block_size = pool->string_block_size;
		pool->string_block = new_string_block;
		pool->string_block_size = new_string_block_size;

        first_free_node_offset = pool->dummy_node_offset;
        first_free_node = strpool_get_string_node(pool, first_free_node_offset);
        // first_free_node->front_node_offset doesn't change
        first_free_node->size = new_string_block_size - old_string_block_size;
        first_free_node->string_length = 0;

        strpool_free(old_string_block);
    }
    else
    {
        pool->string_block = new_string_block;
        pool->string_block_size = new_string_block_size;
        memset(pool->string_block, 0, pool->string_block_size);

        first_free_node = strpool_get_string_node(pool, first_free_node_offset);
        first_free_node->front_node_offset = pool->dummy_node_offset;
        first_free_node->size = new_string_block_size - STRPOOL_DUMMY_NODE_SIZE;
        first_free_node->string_length = 0;

    }

    pool->dummy_node_offset = pool->string_block_size - STRPOOL_DUMMY_NODE_SIZE;
    strpool_string_node *dummy_node = strpool_get_string_node(pool, pool->dummy_node_offset);
    dummy_node->front_node_offset = first_free_node_offset;
    dummy_node->size = -pool->dummy_node_offset;
    dummy_node->string_length = STRPOOL_DUMMY_NODE_LENGTH_SENTINEL;

    // make the link circular
    int32_t first_node_offset = pool->dummy_node_offset + dummy_node->size;
    strpool_string_node *first_node = strpool_get_string_node(pool, first_node_offset);
    first_node->front_node_offset = pool->dummy_node_offset;

    strpool_string_node *front_node = strpool_get_string_node(pool, first_free_node->front_node_offset);
    if (front_node->string_length == 0)
    {
        dummy_node->front_node_offset = first_free_node->front_node_offset;
        front_node->size += first_free_node->size;
        first_free_node_offset = first_free_node->front_node_offset;
    }

    pool->first_free_node_offset = first_free_node_offset;
}

int32_t strpool_init(strpool *pool, int32_t string_block_size, int32_t hashslot_capacity, int32_t entry_capacity)
{
	if (string_block_size < STRPOOL_STRING_BLOCK_MIN_SIZE) string_block_size = STRPOOL_STRING_BLOCK_MIN_SIZE;
    string_block_size = memory_align(string_block_size, sizeof(size_t));
    strpool_extend_string_block(pool, string_block_size);

    int32_t hashslot_buffer_size = hashslot_capacity * sizeof(strpool_hashslot);
    pool->hashslots = (strpool_hashslot*)strpool_malloc(hashslot_buffer_size);
    assert(pool->hashslots);
    pool->hashslot_capacity = hashslot_capacity;
    memset(pool->hashslots, 0, hashslot_buffer_size);

    int32_t entry_buffer_size = entry_capacity * sizeof(strpool_entry);
    pool->entries = (strpool_entry *)strpool_malloc(entry_buffer_size);
    assert(pool->entries);
    pool->entry_capacity = entry_capacity;
    pool->entry_count = 0;
    memset(pool->entries, 0, entry_buffer_size);

    pool->dummy_free_entry_index = 0;
    strpool_entry &dummy_free_entry = pool->entries[pool->dummy_free_entry_index];
    dummy_free_entry.prev_free_entry_index = pool->dummy_free_entry_index;
    dummy_free_entry.next_free_entry_index = pool->dummy_free_entry_index;
    pool->entry_count++;

    return 1;
}

int32_t strpool_store_string(strpool *pool, const char *string, int str_length)
{
    int32_t string_data_offset = -1;

    int aliged_need_size = memory_align(sizeof(strpool_string_node) + str_length + sizeof('\0'), sizeof(size_t));
    int32_t rover_offset = pool->first_free_node_offset;
    while (1)
    {
        strpool_string_node *node = strpool_get_string_node(pool, rover_offset);
        if (node->string_length == 0 && node->size > aliged_need_size)
        {
            break;
        }
        rover_offset = rover_offset + node->size;
        if (rover_offset == pool->first_free_node_offset)
        {
            rover_offset = -1;
			break;
        }
    }

    if (rover_offset < 0)
    {
        strpool_extend_string_block(pool, memory_align(pool->string_block_size * 2 + aliged_need_size, sizeof(size_t)));
        rover_offset = pool->first_free_node_offset;
    }

    int32_t aligned_new_node_size = memory_align(sizeof(strpool_string_node)+ str_length + sizeof('\0'), sizeof(size_t));
    strpool_string_node *new_node = strpool_get_string_node(pool, rover_offset);
    if (new_node->size > aliged_need_size)
    {
        string_data_offset = rover_offset + sizeof(strpool_string_node);
        char *string_data = (char *)new_node + sizeof(strpool_string_node);
        // memcpy requires restrict pointer, we assume it's safe here.
        memcpy(string_data, string, str_length);
        string_data[str_length] = '\0';
        new_node->string_length = str_length;

        pool->first_free_node_offset = rover_offset + new_node->size;

        int32_t size_left = new_node->size - aligned_new_node_size;
        if (size_left >= STRPOOL_STRING_BLOCK_MIN_SIZE)
        {
            new_node->size = aligned_new_node_size;

            int32_t next_free_node_offset = rover_offset + aligned_new_node_size;
            strpool_string_node *next_free_node = strpool_get_string_node(pool, next_free_node_offset);
            next_free_node->size = size_left;
            next_free_node->string_length = 0;
            next_free_node->front_node_offset = rover_offset;

            pool->first_free_node_offset = next_free_node_offset;
        }
    }

    assert(string_data_offset >= 0);

    return string_data_offset;
}

/**
 * Return the handle to the string if it already exists in the string pool, otherwise
 * inject the string into the string pool and return the handle.
 * @param input_string The input string doesn't need to be null-terminated.
 */
strpool_handle strpool_get_handle(strpool *pool, const char *input_string, int input_str_length)
{
    uint32_t current_hash = strpool_calc_string_hash(input_string, input_str_length);
    uint32_t base_slot_index = current_hash % (uint32_t)pool->hashslot_capacity;
    strpool_hashslot &base_slot = pool->hashslots[base_slot_index];

    /* 
     * Check if the input_string is already in the pool.
     */

    uint32_t slot_index = base_slot_index;
    uint32_t first_free_slot_index = base_slot_index;
    int32_t base_count = base_slot.base_count;

    while (base_count)
    {
        const strpool_hashslot &slot = pool->hashslots[slot_index];
        uint32_t slot_hash = slot.string_hash;

        // Record the first free hash slot to the right of the base slot.
        if (slot_hash == 0 && pool->hashslots[first_free_slot_index].string_hash != 0)
        {
            first_free_slot_index = slot_index;
        }

        uint32_t slot_hash_base_index = slot_hash % (uint32_t)pool->hashslot_capacity;
        if (slot_hash_base_index != base_slot_index)
        {
            // The hash key of the current slot being tested is associated with 
            // a different base slot.
            continue;
        }
        base_count--;

        // Two different hash keys could be assigned to the same base slot, 
        // for example, hash_1 = pool->hashslot_size and hash_2 = 2 * pool->hashslot_size.
        if (slot_hash == current_hash)
        {
            strpool_entry &entry = pool->entries[slot.entry_index];
			char *string_data = pool->string_block + entry.string_data_offset;
            if (memcmp(string_data, input_string, input_str_length) == 0)
            {
                entry.ref_count++;
                strpool_handle result = {slot.entry_index};
                return result;
            }
        }

        slot_index = (slot_index + 1) % (uint32_t)pool->hashslot_capacity;
    }

    /*
     * Add an entry for the new input_string.
     */

    if (pool->entry_count >= pool->hashslot_capacity - pool->hashslot_capacity / pool->hashslots_load_divider)
    {
        /* Expand hash slots. */

        int32_t old_hashslot_capacity = pool->hashslot_capacity;
        strpool_hashslot *old_hashslots = pool->hashslots;
        pool->hashslot_capacity = old_hashslot_capacity * 2;
        pool->hashslots = (strpool_hashslot *)strpool_malloc(pool->hashslot_capacity * sizeof(*pool->hashslots));
        assert(pool->hashslots);
        memset(pool->hashslots, 0, pool->hashslot_capacity * sizeof(*pool->hashslots));

        for (int i = 0; i < old_hashslot_capacity; ++i)
        {
            uint32_t old_slot_string_hash = old_hashslots[i].string_hash;
            if (old_slot_string_hash)
            {
                int32_t base_slot_index = old_slot_string_hash % pool->hashslot_capacity;
                int32_t slot_index = base_slot_index;
                while (pool->hashslots[slot_index].string_hash)
                {
                    slot_index = (slot_index + 1) % pool->hashslot_capacity;
                }
                pool->hashslots[slot_index].string_hash = old_slot_string_hash;
                pool->hashslots[slot_index].entry_index = old_hashslots[i].entry_index;
                pool->hashslots[base_slot_index].base_count++;
                pool->entries[old_hashslots[i].entry_index].hashslot = slot_index;
            }
        }

        strpool_free(old_hashslots);
    }

    while (pool->hashslots[first_free_slot_index].string_hash != 0)
    {
        // If we couldn't find a free slot in between slots tested above, continue searching.
        first_free_slot_index = (first_free_slot_index + 1) % pool->hashslot_capacity;
    }

    int32_t new_entry_index = 0;
    if (pool->entry_count >= pool->entry_capacity)
    {
        strpool_entry &dummy_free_entry = pool->entries[pool->dummy_free_entry_index];
        if (dummy_free_entry.next_free_entry_index == pool->dummy_free_entry_index)
        {
            /* Expand entry array. */

            int32_t old_entry_capacity = pool->entry_capacity;
            pool->entry_capacity = old_entry_capacity * 2;
            strpool_entry *new_entry_buffer = (strpool_entry *)strpool_malloc(pool->entry_capacity * sizeof(*pool->entries));
            assert(new_entry_buffer);
            memcpy(new_entry_buffer, pool->entries, old_entry_capacity * sizeof(*pool->entries));
            strpool_free(pool->entries);
            pool->entries = new_entry_buffer;

            new_entry_index = pool->entry_count;
            pool->entry_count++;
        }
        else
        {
            new_entry_index = dummy_free_entry.next_free_entry_index;

            // delete new_entry_index from free entry list
            strpool_entry &new_entry = pool->entries[new_entry_index];
            dummy_free_entry.next_free_entry_index = new_entry.next_free_entry_index;
            strpool_entry &next_free_entry = pool->entries[new_entry.next_free_entry_index];
            next_free_entry.prev_free_entry_index = pool->dummy_free_entry_index;
            pool->free_entry_list_count--;
        }
    }
    else
    {
        new_entry_index = pool->entry_count;
        pool->entry_count++;
    }

    strpool_entry &new_entry = pool->entries[new_entry_index];
    new_entry.string_hash = current_hash;
    new_entry.hashslot = first_free_slot_index;
    new_entry.ref_count++;

    strpool_hashslot &new_slot = pool->hashslots[first_free_slot_index];
    new_slot.string_hash = current_hash;
    new_slot.entry_index = new_entry_index;

    pool->hashslots[base_slot_index].base_count++;

    /* 
     * Store the new input_string.
     */

    int32_t string_data_offset = strpool_store_string(pool, input_string, input_str_length);
    new_entry.string_data_offset = string_data_offset;

    strpool_handle result = {new_entry_index};
    return result;
}

int strpool_discard_handle(strpool *pool, strpool_handle handle)
{
    strpool_entry &entry = pool->entries[handle.entry_index];

    if (entry.ref_count > 1)
    {
        entry.ref_count--;
        return entry.ref_count;
    }

    /* Recycle string memory. */

    int32_t node_offset = entry.string_data_offset - sizeof(strpool_string_node);
    strpool_string_node *node = strpool_get_string_node(pool, node_offset);

    strpool_string_node *front_node = strpool_get_string_node(pool, node->front_node_offset);

    int32_t next_node_offset = node_offset + node->size;
    strpool_string_node *next_node = strpool_get_string_node(pool, next_node_offset);

    if (front_node->string_length == 0)
    {
        /* Conjoin this node and the free one in front. */

        next_node->front_node_offset = node->front_node_offset;
        front_node->size += node->size;

        node_offset = node->front_node_offset;
        node = front_node;
    }

    if (next_node->string_length == 0)
    {
        int32_t next_2_node_offset = next_node_offset + next_node->size;
        strpool_string_node *next_2_node = strpool_get_string_node(pool, next_2_node_offset);
        next_2_node->front_node_offset = node->front_node_offset;
        node->size += next_node->size;
    }

    pool->first_free_node_offset = node_offset;

    /* Recycle entry and hashslot */

    int32_t base_slot_index = entry.string_hash % pool->hashslot_capacity;
    pool->hashslots[base_slot_index].base_count--;
    pool->hashslots[entry.hashslot].string_hash = 0;

    if (handle.entry_index == pool->entry_count - 1)
    {
        pool->entry_count--;
    }
    else
    {
        // insert the entry in between the dummy entry and its next one
        strpool_entry &dummy_free_entry = pool->entries[pool->dummy_free_entry_index];
        entry.prev_free_entry_index = pool->dummy_free_entry_index;
        entry.next_free_entry_index = dummy_free_entry.next_free_entry_index;
        strpool_entry &next_free_entry = pool->entries[dummy_free_entry.next_free_entry_index];
        next_free_entry.prev_free_entry_index= handle.entry_index;
        dummy_free_entry.next_free_entry_index = handle.entry_index;
        pool->free_entry_list_count++;
    }

    return 0;
}

const char *strpool_get_string(strpool *pool, strpool_handle handle, int32_t *str_length_out = 0)
{
    const strpool_entry &entry = pool->entries[handle.entry_index];
    const char *result = (const char *)(pool->string_block + entry.string_data_offset);
    if (str_length_out != 0)
    {
        strpool_string_node *stringnode = (strpool_string_node *)(result - sizeof(strpool_string_node));
        *str_length_out = stringnode->string_length;
    }
	return result;
}


/*====================
    Networds app
====================*/

#define NETWORD_MALLOC_SENTINEL 0x977abc0

void *nw_malloc(size_t size)
{
    char *mem = (char *)malloc(size + sizeof(size_t) + sizeof(int32_t));
    *(size_t *)mem = size;
    char *result = mem + sizeof(size_t);
    *(uint32_t *)(result + size) = NETWORD_MALLOC_SENTINEL;
    return (void *)result;
}

void nw_free(void *ptr)
{
    char *real_ptr = (char *)ptr - sizeof(size_t);
    size_t size = *(size_t *)real_ptr;
    uint32_t sentinel = *(uint32_t *)(real_ptr + sizeof(size_t) + size);
    assert(sentinel == NETWORD_MALLOC_SENTINEL);
    free(real_ptr);
}

struct netword_t
{
    strpool_handle this_word;
    int related_words_count;
    strpool_handle *related_words;
    int related_words_capacity;
    int visits;

    ~netword_t()
    {
        if (related_words != 0)
        {
            nw_free(related_words);
        }
    }
};

struct networdpool_t
{
    netword_t *words = 0;
    int words_count = 0;
    int pool_capacity = 0;

    ~networdpool_t()
    {
        if (words != 0)
        {
            nw_free(words);
        }
    }
};

void nw_networdpool_init(networdpool_t *wordspool, int32_t pool_capacity)
{
    if (pool_capacity < 3)
    {
        pool_capacity = 3;
    } 
    wordspool->words = (netword_t *)nw_malloc(pool_capacity * sizeof(netword_t));
    wordspool->pool_capacity = pool_capacity;
    wordspool->words_count = 0;
}

netword_t *nw_make_word(networdpool_t *wordspool, const char *word, int word_length, strpool *stringpool)
{
    if (wordspool->words_count >= wordspool->pool_capacity - 1)
    {
        int new_wordspool_capacity = wordspool->pool_capacity * 2;
        netword_t *new_wordspool = (netword_t *)nw_malloc(new_wordspool_capacity * sizeof(netword_t));
        memcpy((char *)new_wordspool, wordspool->words, wordspool->words_count * sizeof(netword_t));
        nw_free(wordspool->words);
        wordspool->words = new_wordspool;
        wordspool->pool_capacity = new_wordspool_capacity;
    }
    netword_t *result = &wordspool->words[wordspool->words_count++];
    result->this_word = strpool_get_handle(stringpool, word, word_length);

    result->related_words_count = 0;
    result->related_words_capacity = 3;
    result->related_words = (strpool_handle *)nw_malloc(result->related_words_capacity * sizeof(strpool_handle));

    result->visits = 1;
    return result;
}

void nw_add_related_word(netword_t *word, const char *related_word, int related_word_length, strpool *stringpool)
{
    if (word->related_words_count >= word->related_words_capacity - 1)
    {
        int new_related_words_capacity = word->related_words_capacity * 2;
        strpool_handle *new_related_words = (strpool_handle *)nw_malloc(new_related_words_capacity * sizeof(strpool_handle));
        for (int i = 0; i < word->related_words_count; ++i)
        {
            new_related_words[i] = word->related_words[i];
        }
        nw_free(word->related_words);
        word->related_words = new_related_words;
        word->related_words_capacity = new_related_words_capacity;
    }
    word->related_words[word->related_words_count++] = strpool_get_handle(stringpool, related_word, related_word_length);
}

/*========================
    Json Reader/Writer
========================*/

const char *nw_json_error(const char *errmsg)
{
    static const size_t error_msg_size = 256;
    static char error_msg[error_msg_size];
    if (errmsg != 0)
    {
        lt_str_ncopy(error_msg, error_msg_size, errmsg);
        assert(false);
    }
    return error_msg;
};

char nw_next_nonwhitespace(const char *str, size_t &pos)
{
    char c = *(str + pos);
    while (c == ' ' || c == '\n' || c == '\t' || c == '\r' || c == '\v')
    {
        pos++;
        c = *(str + pos);
    }
	pos++;
    return c;
}

/**
 * @param pos Position of the first character of a string.
 * @return The length of the string skipped.
 */
int nw_json_skip_string(const char *json_str, size_t &pos)
{
    int str_length = 0;

    while (*(json_str + pos) != '\"')
    {
        pos++;
        str_length++;
        if (str_length > 128)
        {
            // TODO: log string too big
            str_length = 0;
            break;
        }
    }
    pos++;
    return str_length;
}

/**
 * @param pos Position of the first character of a integer number.
 * @return The integer number skipped.
 */
int32_t nw_json_skip_int32(const char *json_str, size_t &pos)
{
	char c = *(json_str + pos);
    while (c == ' ' || c == '\n' || c == '\t' || c == '\r' || c == '\v')
    {
        pos++;
        c = *(json_str + pos);
    }

    int32_t sign = 1;
    if (c == '-')
    {
        sign = -1;
        pos++;
        c = *(json_str + pos);
    }

    if (c < '0' || c > '9')
    {
        nw_json_error("Json invalid integer number character!");
        return 0;
    }

    int32_t result = 0;
    while (c >= '0' && c <= '9')
    {
        result = result * 10 + c - '0';
        // check for integer overflow
        pos++;
        c = *(json_str + pos);
    }
    result *= sign;

    if (c == ' ' || c == '\n' || c == '\t' || c == '\r' || c == '\v')
    {
        return result;
    }
    else if (c == ',')
    {
        return result;
    }
    else if (c == ']')
    {
        return result;
    }
    else if (c == '}')
    {
        return result;
    }
    else
    {
        nw_json_error("Json invalid integer number character!");
        return 0;
    }
}

const uint32_t json_collection_type_array = 0;
const uint32_t json_collection_type_object = 1;

/**
 * Maximum collection depth is 32.
 */
int nw_json_read(const char *json_str, size_t json_str_length, networdpool_t *wordspool, strpool *stringpool)
{
    if (json_str == 0 || json_str_length == 0)
    {
        return 1;
    }

    int read_result = 0;

    // the position of the leading bit represents the collection depth
    uint32_t collection_depth = 0;
    // each bit represents the collection type at the depth of the bit position
    uint32_t collection_types[32];

    size_t json_str_pos = 0;
    char next_char = nw_next_nonwhitespace(json_str, json_str_pos);
    if (next_char != '[')
    {
        nw_json_error("The first non-whilespace character has to be \'[\'!");
        read_result = 1;
    }
    collection_depth = 1;
    collection_types[collection_depth - 1] = json_collection_type_array;
    next_char = nw_next_nonwhitespace(json_str, json_str_pos);
    netword_t *current_word = 0;

    while (json_str_pos <= json_str_length)
    {
        switch (next_char)
        {
            case '{': 
            {
                collection_depth += 1;
                collection_types[collection_depth - 1] = json_collection_type_object;
                if (current_word != 0)
                {
                    nw_json_error("Last netword has not finished parsing!");
                    read_result = 1;
                }
                goto parsing_next_key_pair;
            } break;

            case '}':
            {
                if (collection_types[collection_depth - 1] != json_collection_type_object)
                {
                    nw_json_error("Collection type mismatch!");
                    read_result = 1;
                }
                collection_depth -= 1;
                if (current_word == 0)
                {
                    nw_json_error("Currently being parsed networds is null!");
                    read_result = 1;
                }
                current_word = 0;
                goto parsing_next_character;
            } break;

            case ']':
            {
                if (collection_types[collection_depth - 1] != json_collection_type_array)
                {
                    nw_json_error("Collection type mismatch!");
                    read_result = 1;
                }
                collection_depth -= 1;
                if (collection_depth != 0)
                {
                    nw_json_error("Collection unclosed!");
                    read_result = 1;
                }
                goto parsing_finished;
            } break;

            case ',':
            {
                if (collection_types[collection_depth - 1] == json_collection_type_object)
                {
                    goto parsing_next_key_pair;
                }
                else
                {
                    goto parsing_next_character;
                }
            } break;

            default:
            {
                nw_json_error("Unexpected character!");
                read_result = 1;
            } break;
        }

        parsing_next_key_pair:

        next_char = nw_next_nonwhitespace(json_str, json_str_pos);
        if (next_char != '\"')
        {
            nw_json_error("Non-conforming JSON file, expecting \'\"\'!");
            read_result = 1;
        }

        if (lt_str_ncompare(json_str + json_str_pos, "word\"", 5) == 0)
        {
            json_str_pos += 5;
            next_char = nw_next_nonwhitespace(json_str, json_str_pos);
            if (next_char != ':')
            {
                nw_json_error("Non-conforming JSON file, expecting \':\'!");
                read_result = 1;
            }
            next_char = nw_next_nonwhitespace(json_str, json_str_pos);
            if (next_char != '\"')
            {
                nw_json_error("Non-conforming JSON file, expecting \'\"\'!");
                read_result = 1;
            }
            const char *new_word = json_str + json_str_pos;
            int new_word_length = nw_json_skip_string(json_str, json_str_pos);
            current_word = nw_make_word(wordspool, new_word, new_word_length, stringpool);
            goto parsing_next_character;
        }
        else if (lt_str_ncompare(json_str + json_str_pos, "relatives\"", 10) == 0)
        {
            json_str_pos += 10;
            next_char = nw_next_nonwhitespace(json_str, json_str_pos);
            if (next_char != ':')
            {
                nw_json_error("Non-conforming JSON file, expecting \':\'!");
                read_result = 1;
            }
            next_char = nw_next_nonwhitespace(json_str, json_str_pos);
            if (next_char != '[')
            {
                nw_json_error("Expecting \'[\' for an array of related words!");
                read_result = 1;
            }
            collection_depth += 1;
            collection_types[collection_depth - 1] = json_collection_type_array;
            next_char = nw_next_nonwhitespace(json_str, json_str_pos);
            while (next_char == '\"')
            {
                const char *new_word = json_str + json_str_pos;
                int new_word_length = nw_json_skip_string(json_str, json_str_pos);
                nw_add_related_word(current_word, new_word, new_word_length, stringpool);
                next_char = nw_next_nonwhitespace(json_str, json_str_pos);
                if (next_char != ',')
                {
                    break;
                }
                else
                {
                    next_char = nw_next_nonwhitespace(json_str, json_str_pos);
                }
            }
            if (next_char != ']')
            {
                nw_json_error("Expecting \']\' to close the array of related words!");
                read_result = 1;
            }
            if (collection_types[collection_depth - 1] != json_collection_type_array)
            {
                nw_json_error("Collection type mismatch!");
                read_result = 1;
            }
            collection_depth -= 1;
        }
        else if (lt_str_ncompare(json_str + json_str_pos, "visits\"", 7) == 0)
        {
            json_str_pos += 7;
            next_char = nw_next_nonwhitespace(json_str, json_str_pos);
            if (next_char != ':')
            {
                nw_json_error("Non-conforming JSON file, expecting \':\'!");
                read_result = 1;
            }
            int32_t visitsn = nw_json_skip_int32(json_str, json_str_pos);
            current_word->visits = visitsn;
            goto parsing_next_character;
        }
        else
        {
            nw_json_error("Unrecognized key!");
            read_result = 1;
        }

        parsing_next_character:

		next_char = nw_next_nonwhitespace(json_str, json_str_pos);
    }

    parsing_finished:

	return read_result;
}

void nw_json_write_whitespaces(char *json_buffer, size_t &json_buffer_pos, int whitespace_count)
{
    while (whitespace_count > 0)
    {
        json_buffer[json_buffer_pos] = ' ';
        json_buffer_pos++;
        whitespace_count--;
    }
}

void nw_json_write_string(char *json_buffer, size_t &json_buffer_pos, const char *string, int string_length)
{
    json_buffer[json_buffer_pos++] = '\"';
    for (int i = 0; i < string_length; ++i)
    {
        json_buffer[json_buffer_pos++] = string[i];
    }
    json_buffer[json_buffer_pos++] = '\"';
}

void nw_json_write_int32(char *json_buffer, size_t &json_buffer_pos, int n)
{
    static const int MaxDigitCount = 16;
    static char number[MaxDigitCount];

    int sign = (n >= 0 ? 1 : -1);
    n *= sign;
    int digit_pos = MaxDigitCount - 1;
    do
    {
        int d = n % 10;
        number[digit_pos] = '0' + d;
        digit_pos--;
        n /= 10;
    } while (n > 0);
    if (sign == -1)
    {
        json_buffer[json_buffer_pos++] = '-';
    }
    while (++digit_pos < MaxDigitCount)
    {
        json_buffer[json_buffer_pos++] = number[digit_pos];
    }
}

int nw_json_write(networdpool_t *wordspool, char *json_buffer, size_t json_buffer_size, strpool *stringpool)
{
    static const char key_str_word[5] = "word";
    static const char key_str_relatives[10] = "relatives";
    static const char key_str_visits[7] = "visits";

    size_t json_buffer_pos = 0;
    json_buffer[json_buffer_pos++] = '[';
    json_buffer[json_buffer_pos++] = '\n';

    for (int i_word = 0; i_word < wordspool->words_count; ++i_word)
    {
        netword_t *netword = &wordspool->words[i_word];

        nw_json_write_whitespaces(json_buffer, json_buffer_pos, 4);
        json_buffer[json_buffer_pos++] = '{';
        json_buffer[json_buffer_pos++] = '\n';

        nw_json_write_whitespaces(json_buffer, json_buffer_pos, 8);
        nw_json_write_string(json_buffer, json_buffer_pos, key_str_word, lt_str_length(key_str_word));
        json_buffer[json_buffer_pos++] = ' ';
        json_buffer[json_buffer_pos++] = ':';
        json_buffer[json_buffer_pos++] = ' ';
        const char *word = strpool_get_string(stringpool, netword->this_word);
        nw_json_write_string(json_buffer, json_buffer_pos, word, lt_str_length(word));
        json_buffer[json_buffer_pos++] = ',';
        json_buffer[json_buffer_pos++] = '\n';

        nw_json_write_whitespaces(json_buffer, json_buffer_pos, 8);
        nw_json_write_string(json_buffer, json_buffer_pos, key_str_relatives, lt_str_length(key_str_relatives));
        json_buffer[json_buffer_pos++] = ' ';
        json_buffer[json_buffer_pos++] = ':';
        json_buffer[json_buffer_pos++] = ' ';
        json_buffer[json_buffer_pos++] = '[';
        for (int j = 0; j < netword->related_words_count; ++j)
        {
            word = strpool_get_string(stringpool, netword->related_words[j]);
            nw_json_write_string(json_buffer, json_buffer_pos, word, lt_str_length(word));
            if (j < netword->related_words_count - 1)
            {
                json_buffer[json_buffer_pos++] = ',';
                json_buffer[json_buffer_pos++] = ' ';
            }
        }
        json_buffer[json_buffer_pos++] = ']';
        json_buffer[json_buffer_pos++] = ',';
        json_buffer[json_buffer_pos++] = '\n';

        nw_json_write_whitespaces(json_buffer, json_buffer_pos, 8);
        nw_json_write_string(json_buffer, json_buffer_pos, key_str_visits, lt_str_length(key_str_visits));
        json_buffer[json_buffer_pos++] = ' ';
        json_buffer[json_buffer_pos++] = ':';
        json_buffer[json_buffer_pos++] = ' ';
        nw_json_write_int32(json_buffer, json_buffer_pos, netword->visits);
        json_buffer[json_buffer_pos++] = '\n';

        nw_json_write_whitespaces(json_buffer, json_buffer_pos, 4);
        json_buffer[json_buffer_pos++] = '}';

        if (i_word < wordspool->words_count - 1)
        {
            json_buffer[json_buffer_pos++] = ',';
        }
        json_buffer[json_buffer_pos++] = '\n';
    }

    json_buffer[json_buffer_pos++] = ']';
    json_buffer[json_buffer_pos++] = '\0';

    if (json_buffer_pos < json_buffer_size)
    {
        return 0;
    }
    else
    {
        // If we come here, json_buffer is already overflown, need a better way
        // to handle this.
        return 1;
    }
}


/*============================
    Command Line Loop
============================*/

size_t nw_calc_json_buffer_size(networdpool_t *wordspool, strpool *stringpool)
{
    // approximation, + 1 for '\n'
    size_t word_line_size = 18 + 1;
    size_t relatives_line_size = 25 + 1;
    size_t visits_line_size = 23 + 1;
    size_t open_brace_line = 5 + 1;
    size_t close_brace_line = 6 + 1;

    size_t result = (word_line_size + relatives_line_size + visits_line_size + 
                      open_brace_line + close_brace_line) * wordspool->words_count;

    for (int i = 0; i < wordspool->words_count; ++i)
    {
        netword_t *word = wordspool->words + i;

        int32_t word_length = 0; 
        strpool_get_string(stringpool, word->this_word, &word_length);
        word_length += 2;
        result += word_length;

        for (int j = 0; j < word->related_words_count; ++j)
        {
            strpool_handle relative = word->related_words[j];
            int32_t relative_length = 0;
            strpool_get_string(stringpool, relative, &relative_length);
            relative_length += 3;
            result += relative_length;
        }
    }

    result += 2; // outer most array bracketsk
    result = result + result / 4; // to be safe

    return result;
}

/**
 * 
 */
int nw_save(networdpool_t *wordspool, strpool *stringpool)
{
    static const char *netword_filename = "networds.json";
    size_t netword_filename_length = lt_str_length(netword_filename);

    const size_t backup_filename_size = 128;
    char backup_filename[backup_filename_size];
    bool backup_made = false;

    FILE *netword_file = 0;
    fopen_s(&netword_file, netword_filename, "r");
    if (netword_file)
    {
        /* If the file already exits, don't just overwrite it, instead change 
         * its name and we will write to a new file with that name. */

        fclose(netword_file);
        netword_file = 0;

        /* Compute backup file name, something like networds_epochseconds.json */

        const size_t seconds_str_size = 64;
        char seconds_str[seconds_str_size];
        size_t seconds_str_pos = seconds_str_size - 1;
        seconds_str[0] = '_';

        size_t seconds = (size_t)time(NULL);
        do
        {
            uint32_t d = seconds % 10;
            seconds_str[seconds_str_pos] = '0' + d;
            seconds_str_pos--;
            seconds /= 10;
        } while (seconds > 0);

        size_t seconds_digit_num = seconds_str_size - seconds_str_pos - 1;

        for (size_t j = 1, i = seconds_str_pos + 1; i < seconds_str_size; ++j, ++i)
        {
            seconds_str[j] = seconds_str[i];
        }

        char backup_filename_no_ext[backup_filename_size];

        lt_str_concat(netword_filename, netword_filename_length - 5, 
                      seconds_str, seconds_digit_num + 1,
                      backup_filename_no_ext, backup_filename_size);

        lt_str_concat(backup_filename_no_ext, netword_filename_length - 5 + seconds_digit_num + 1,
                      ".json", 5, 
                      backup_filename, backup_filename_size);

        int err = rename(netword_filename, backup_filename);
        if (err)
        {
            return 1;
        }
        backup_made = true;
    }

    size_t json_write_buffer_size = nw_calc_json_buffer_size(wordspool, stringpool);
    char *json_write_buffer = (char *)nw_malloc(json_write_buffer_size);
    int write_err = nw_json_write(wordspool, json_write_buffer, json_write_buffer_size, stringpool);

    if (write_err == 0)
    {
        fopen_s(&netword_file, netword_filename, "w");
        if (netword_file)
        {
            fprintf(netword_file, json_write_buffer);
            nw_free(json_write_buffer);
            fclose(netword_file);
        }
        else
        {
            // TODO: log
            if (backup_made)
            {
                rename(backup_filename, netword_filename);
            }
            return 1;
        }
    }

    return 0;
}

void nw_skip_whitespace(const char *cmdline, size_t cmdline_length, size_t &cmdline_pos)
{
    char c = *(cmdline + cmdline_pos);
    while (c == ' ' || c == '\n' || c == '\t' || c == '\r' || c == '\v')
    {
        c = *(cmdline + (++cmdline_pos));
        if (cmdline_pos >= cmdline_length)
        {
            break;
        }
    }
    return;
}

struct nw_cmdl_tokens
{
    static const int MaxTokenNum = 128;
    int token_num = 0;
    int toke_arg_start_position = 0;
    int token_start_positions[MaxTokenNum];
    int token_lengths[MaxTokenNum];
};

enum nw_cmd_e
{
    cmd_unrecognized = 0,
    cmd_exit,
    cmd_new,
    cmd_add,
    cmd_stat,
    cmd_save,
	cmd_count,
};

static const char *nw_cmd_strings[nw_cmd_e::cmd_count] = {
    "unrecognized",
    "exit",
    "new",
    "add",
    "stat",
    "save"
};

/**
 * Create tokens from a comand line string. 
 */
void nw_cmdl_tokenize(const char *cmdline, int cmdline_length, nw_cmdl_tokens &tokens)
{
	size_t cmdline_pos = 0;

    while (1)
    {
        nw_skip_whitespace(cmdline, cmdline_length, cmdline_pos);

        if (*(cmdline + cmdline_pos) == '\n' || 
            *(cmdline + cmdline_pos) == '\0' ||
            cmdline_pos >= cmdline_length)
        {
            break;
        }

        bool openQuote = false;
        if (*(cmdline + cmdline_pos) == '\"')
        {
            ++cmdline_pos;
            openQuote = true;
        }

        tokens.token_start_positions[tokens.token_num] = (int)cmdline_pos++;

        while (1)
        {
            char c = *(cmdline + cmdline_pos);
            if (openQuote)
            {
                if (c == '\"') 
                {
                    break;
                }
            }
            else
            {
                if (c == ' ' || c == '\n' || c == '\t' || c == '\r' || c == '\v' ||
                    c == '\n' || c == '\0' || cmdline_pos >= cmdline_length)
                {
                    break;
                }
            }
            cmdline_pos++;
        }
        tokens.token_lengths[tokens.token_num] = (int)cmdline_pos - tokens.token_start_positions[tokens.token_num];
        tokens.token_num++;

        if (openQuote)
        {
            openQuote = false;
            cmdline_pos++;
        }
    }
}

nw_cmd_e nw_cmdl_get_cmd(const char *cmdline, const nw_cmdl_tokens &tokens)
{
    if (tokens.token_num == 0)
    {
        return nw_cmd_e::cmd_unrecognized;
    }

    const char *nw_cmdstr = cmdline + tokens.token_start_positions[0];
    int nw_cmdstr_length = tokens.token_lengths[0];

    if (nw_cmdstr_length == lt_str_length(nw_cmd_strings[nw_cmd_e::cmd_exit]) && 
        lt_str_ncompare(nw_cmdstr, nw_cmd_strings[nw_cmd_e::cmd_exit], nw_cmdstr_length) == 0)
    {
        return nw_cmd_e::cmd_exit;
    }
    else if (nw_cmdstr_length == 2 && 
             lt_str_ncompare(nw_cmdstr, "nw", nw_cmdstr_length) != 0)
    {
        return nw_cmd_e::cmd_unrecognized;
    }

    if (tokens.token_num == 1)
    {
        return nw_cmd_e::cmd_unrecognized;
    }

    nw_cmdstr = cmdline + tokens.token_start_positions[1];
    nw_cmdstr_length = tokens.token_lengths[1];

    if (nw_cmdstr_length == lt_str_length(nw_cmd_strings[nw_cmd_e::cmd_new]) && 
        lt_str_ncompare(nw_cmdstr, nw_cmd_strings[nw_cmd_e::cmd_new], nw_cmdstr_length) == 0)
    {
        return nw_cmd_e::cmd_new;
    }
    else if (nw_cmdstr_length == lt_str_length(nw_cmd_strings[nw_cmd_e::cmd_add]) && 
             lt_str_ncompare(nw_cmdstr, nw_cmd_strings[nw_cmd_e::cmd_add], nw_cmdstr_length) == 0)
    {
        return nw_cmd_e::cmd_add;
    }
    else if (nw_cmdstr_length == lt_str_length(nw_cmd_strings[nw_cmd_e::cmd_stat]) && 
             lt_str_ncompare(nw_cmdstr, nw_cmd_strings[nw_cmd_e::cmd_stat], nw_cmdstr_length) == 0)
    {
        return nw_cmd_e::cmd_stat;
    }
    else if (nw_cmdstr_length == lt_str_length(nw_cmd_strings[nw_cmd_e::cmd_save]) && 
             lt_str_ncompare(nw_cmdstr, nw_cmd_strings[nw_cmd_e::cmd_save], nw_cmdstr_length) == 0)
    {
        return nw_cmd_e::cmd_save;
    }
    else
    {
        return nw_cmd_e::cmd_unrecognized;
    }
}

/**
 * Read all characters from \ref stream until it meets '\n', '\0' or EOF, or the 
 * amount of characters read equals \ref max_line_length.
 * This function doesn't guarantee \ref line will be null-terminated.
 */
int nw_cmdl_readline(FILE *stream, char *line, int max_line_length)
{
    if (line == 0 || max_line_length <= 0)
    {
        return 0;
    }
    int count = 0;
    while (count < max_line_length)
    {
        char c = getc(stream);
        if (c == EOF)
        {
            if (count == 0)
            {
                return -1;
            }
            else
            {
                break;
            }
        }
        line[count++] = c;
        if (c == '\n' || c == '\0')
        {
            break;
        }
    }
    return count;
}

void nw_cmdl_execute_new(const char *cmdline, nw_cmdl_tokens &tokens, networdpool_t &networdspool, strpool &stringpool)
{
    if (tokens.token_num <= 2)
    {
        printf("No argument following the command \'new\'\n");
    }
    else
    {
        const char *new_word = cmdline + tokens.token_start_positions[2];
        int new_word_length = tokens.token_lengths[2];
        netword_t *netword = nw_make_word(&networdspool, new_word, new_word_length, &stringpool);
        for (int i = 3; i < tokens.token_num; ++i)
        {
            new_word = cmdline + tokens.token_start_positions[i];
            new_word_length = tokens.token_lengths[i];
            nw_add_related_word(netword, new_word, new_word_length, &stringpool);
        }
    }
}

int nw_cmdl_execute_add()
{
	return 0;
}

int nw_cmdl_execute_stat()
{
	return 0;
}

void nw_cmdl_run()
{
    strpool stringpool;
    networdpool_t networdspool;

    FILE *netword_json_file = 0;
    fopen_s(&netword_json_file, "networds.json", "r");
    if (netword_json_file)
    {
        fseek(netword_json_file, 0, SEEK_END);
        size_t file_length = ftell(netword_json_file);
        fseek(netword_json_file, 0, SEEK_SET);

        char *json_buffer = (char *)nw_malloc(file_length);
        json_buffer[file_length - 1] = '\0';
        size_t file_read_length = fread(json_buffer, 1, file_length, netword_json_file);
        if (file_read_length != file_length)
        {
            fprintf(stderr, "File read length isn't equal to file length!\n\n");
        }
        fclose(netword_json_file);

        networdspool.pool_capacity = (int32_t)(file_read_length / 10);
        networdspool.words = (netword_t *)nw_malloc(networdspool.pool_capacity * sizeof(netword_t));

        int32_t stringblock_size = (int32_t)(file_read_length / 2);
        int32_t hashslot_capacity = (int32_t)(file_read_length / 6);
        int32_t entry_capacity = (int32_t)(file_read_length / 4);
        strpool_init(&stringpool, stringblock_size, hashslot_capacity, entry_capacity);

        if (nw_json_read(json_buffer, file_read_length, &networdspool, &stringpool) != 0)
        {
            fprintf(stderr, "Json read error: %s\n\n", nw_json_error(0));
        }
    }
    else
    {
        networdspool.pool_capacity = 10;
        networdspool.words = (netword_t *)nw_malloc(networdspool.pool_capacity * sizeof(netword_t));

        int32_t stringblock_size = 40;
        int32_t hashslot_capacity = 120;
        int32_t entry_capacity = 80;
        strpool_init(&stringpool, stringblock_size, hashslot_capacity, entry_capacity);
    }

    nw_cmdl_tokens cmdl_tokens;
    const int cmdline_max_length = 1024;
    char cmdline[cmdline_max_length];
    char cmdline_length = 0;

    while (1)
    {
        cmdline_length = nw_cmdl_readline(stdin, cmdline, cmdline_max_length);
        nw_cmdl_tokenize(cmdline, cmdline_length, cmdl_tokens);
        nw_cmd_e nw_command = nw_cmdl_get_cmd(cmdline, cmdl_tokens);

        switch(nw_command)
        {
            case nw_cmd_e::cmd_exit:
            {
                return;
            } break;

            case nw_cmd_e::cmd_new:
            {
                nw_cmdl_execute_new(cmdline, cmdl_tokens, networdspool, stringpool);
            } break;

            case nw_cmd_e::cmd_add:
            {
                printf("nw add ...\n\n");
            } break;

            case nw_cmd_e::cmd_stat:
            {
                printf("nw num ...\n\n");
            } break;

            case nw_cmd_e::cmd_save:
            {
                if (nw_save(&networdspool, &stringpool) == 0)
                {
                    printf("New netword json saved.\n\n");
                }
                else
                {
                    printf("Saving failed.\n\n");
                }
            } break;

            case nw_cmd_e::cmd_unrecognized:
            {
                printf("unrecognized command.\n\n");
            } break;
        }

        cmdl_tokens.token_num = 0;
    }
}


/*================
    Unit Tests
================*/

struct sit_test_node;

struct sit_test_registry
{
    sit_test_node *head = 0;
    sit_test_node *current_node = 0;
    int node_count = 0;

    static sit_test_registry *get_instance()
    {
        static sit_test_registry g_test_registry = {0};
        return &g_test_registry;
    }

    static void add_node(sit_test_node *node);
    static void run();
};
        
struct sit_test_node
{
    sit_test_node *next_node;

    sit_test_node()
    {
        sit_test_registry::add_node(this);
    }

	virtual ~sit_test_node() {}

    virtual void run() = 0;
};

void sit_test_registry::add_node(sit_test_node *node)
{
    if (get_instance()->head == 0)
    {
        get_instance()->head = node;
        get_instance()->current_node = node;
    }
    else
    {
        get_instance()->current_node->next_node = node;
        get_instance()->current_node = node;
    }
    get_instance()->node_count++;
}

void sit_test_registry::run()
{
    sit_test_node *node = get_instance()->head;
    int node_count = get_instance()->node_count;
    for (int i = 0; i < node_count; ++i)
    {
        node->run();
        node = node->next_node;
    }
    printf("All tests passed: %d\n\n", node_count);
}

#define SIT_TEST(test_case_name) \
    struct sit_##test_case_name : public sit_test_node { \
        sit_##test_case_name() : sit_test_node() { } \
        void run() override; \
    } sit_node_##test_case_name; \
    void sit_##test_case_name::run()
    

namespace NetwordsTests
{
    SIT_TEST(next_pow2_test_input_zero_return_one)
    {
        uint32_t result = next_pow2(0);
        assert(result == 1);
    }

    SIT_TEST(memory_align_test_normal)
    {
        uint32_t result = memory_align(0x000f, 8);
        assert(result == 0x0010);
        result = memory_align(0x0008, 8);
        assert(result == 0x0008);
    }

    SIT_TEST(lt_str_ncompare_test_various)
    {
        assert(lt_str_ncompare("aabb", "aabbc", 4) == 0);
        assert(lt_str_ncompare("aabb", "aabbc", 5) < 0);
        assert(lt_str_ncompare("aAbb", "aabb", 4) < 0);
        assert(lt_str_ncompare("aabc", "aabb", 4) > 0);
    }

    SIT_TEST(lt_str_concat_test_various)
    {
        const int str0_size = 5;
        char str0[str0_size] = "1234";

        const int str1_size = 10;
        char str1[str1_size] = "123456789";

        const int dest_buffer_size = 20;
        char dest_buffer[dest_buffer_size];

        int concat_result = lt_str_concat(str0, str0_size - 1, str1, str1_size - 1, dest_buffer, dest_buffer_size);
        assert(concat_result == 0);
        int dest_string_length = lt_str_length(dest_buffer);
        assert(dest_string_length == 13);
        assert(lt_str_ncompare(dest_buffer, "1234123456789", dest_string_length) == 0); 

        concat_result = lt_str_concat(str0, str0_size - 1, str1, str1_size - 1, dest_buffer, 4);
        assert(concat_result == 1);

        concat_result = lt_str_concat(str0, str0_size - 1, str1, str1_size - 1, dest_buffer, 12);
        assert(concat_result == 2);
    }

    SIT_TEST(strpool_init_test)
    {
        const int32_t pool_string_block_size = 100;

        strpool pool;
        strpool_init(&pool, pool_string_block_size, 20, 20);

        strpool_string_node *dummy_node = strpool_get_string_node(&pool, pool.dummy_node_offset);
        assert(dummy_node->string_length == STRPOOL_DUMMY_NODE_LENGTH_SENTINEL);

        strpool_string_node *first_free_node = strpool_get_string_node(&pool, pool.first_free_node_offset);
        assert(first_free_node->front_node_offset == pool.dummy_node_offset);
        assert(dummy_node->front_node_offset == pool.first_free_node_offset);
    }

    SIT_TEST(strpool_get_handle_test_normal)
    {
        const char *test_str0 = "good stuff";
        strpool pool;
        strpool_init(&pool, 100, 20, 20);

        strpool_handle handle = strpool_get_handle(&pool, test_str0, lt_str_length(test_str0));
        const char *result_str0 = strpool_get_string(&pool, handle);
        assert(lt_str_ncompare(test_str0, result_str0, lt_str_length(result_str0)) == 0);
    }

    SIT_TEST(strpool_get_handle_test_input_existing_string)
    {
        const char *test_str0 = "better stuff";

        strpool pool;
        strpool_init(&pool, 100, 20, 20);

        strpool_handle handle0 = strpool_get_handle(&pool, test_str0, lt_str_length(test_str0));
        strpool_handle handle1 = strpool_get_handle(&pool, test_str0, lt_str_length(test_str0));
		assert(handle0 == handle1);

        const char *result_str1 = strpool_get_string(&pool, handle1);
        assert(lt_str_ncompare(test_str0, result_str1, lt_str_length(result_str1)) == 0);
    }

    SIT_TEST(strpool_get_handle_test_insufficient_initial_string_block)
    {
        const char *test_str0 = "the initial string block is too small";

        strpool pool;
        strpool_init(&pool, 32, 10, 5);

        strpool_handle handle = strpool_get_handle(&pool, test_str0, lt_str_length(test_str0));
        const char *result_str0 = strpool_get_string(&pool, handle);
        assert(lt_str_ncompare(test_str0, result_str0, lt_str_length(result_str0)) == 0);
    }

    SIT_TEST(strpool_get_handle_test_insufficient_initial_entry_capacity)
    {
        strpool pool;
        strpool_init(&pool, 64, 10, 2);
        
        const char *str0 = "antithetical";
        strpool_handle handle0 = strpool_get_handle(&pool, str0, lt_str_length(str0));
        const char *str1 = "chicanery";
        strpool_handle handle1 = strpool_get_handle(&pool, str1, lt_str_length(str1));
        const char *str2 = "on the up and up";
        strpool_handle handle2 = strpool_get_handle(&pool, str2, lt_str_length(str2));

        assert(lt_str_ncompare(strpool_get_string(&pool, handle0), str0, lt_str_length(str0)) == 0);
        assert(lt_str_ncompare(strpool_get_string(&pool, handle1), str1, lt_str_length(str1)) == 0);
        assert(lt_str_ncompare(strpool_get_string(&pool, handle2), str2, lt_str_length(str2)) == 0);

        assert(pool.entry_capacity > 2);
    }

    SIT_TEST(strpool_get_handle_test_insufficient_initial_hashslot_capacity)
    {
        strpool pool;
        pool.hashslots_load_divider = 3;
        strpool_init(&pool, 64, 3, 10);
        
        const char *str0 = "antithetical";
        strpool_handle handle0 = strpool_get_handle(&pool, str0, lt_str_length(str0));
        const char *str1 = "chicanery";
        strpool_handle handle1 = strpool_get_handle(&pool, str1, lt_str_length(str1));
        const char *str2 = "on the up and up";
        strpool_handle handle2 = strpool_get_handle(&pool, str2, lt_str_length(str2));

        assert(lt_str_ncompare(strpool_get_string(&pool, handle0), str0, lt_str_length(str0)) == 0);
        assert(lt_str_ncompare(strpool_get_string(&pool, handle1), str1, lt_str_length(str1)) == 0);
        assert(lt_str_ncompare(strpool_get_string(&pool, handle2), str2, lt_str_length(str2)) == 0);
    }

    STRPOOL_STRING_HASH_F(strpool_same_hash_stub)
    {
        return 1771;
    }

    SIT_TEST(strpool_get_handle_test_existing_string_same_hash)
    {
        strpool_calc_string_hash = strpool_same_hash_stub;

        const char *test_str0 = "better stuff";
        const char *test_str1 = "awesome stuff";

        strpool pool;
        strpool_init(&pool, 100, 20, 20);

        strpool_handle handle0 = strpool_get_handle(&pool, test_str0, lt_str_length(test_str0));
        strpool_handle handle1 = strpool_get_handle(&pool, test_str1, lt_str_length(test_str1));
        assert(handle0 != handle1);

        const strpool_entry &entry0 = pool.entries[handle0.entry_index];
        const strpool_entry &entry1 = pool.entries[handle1.entry_index];
        assert(entry1.hashslot - entry0.hashslot == 1);

        strpool_calc_string_hash = strpool_calculate_string_hash;
    }

    SIT_TEST(strpool_get_handle_test_insufficient_hashslot_capacity_strings_same_hash)
    {
        strpool_calc_string_hash = strpool_same_hash_stub;

        strpool pool;
        pool.hashslots_load_divider = 3;
        strpool_init(&pool, 64, 4, 10);
        
        const char *str0 = "antithetical";
        strpool_handle handle0 = strpool_get_handle(&pool, str0, lt_str_length(str0));
        const char *str1 = "chicanery";
        strpool_handle handle1 = strpool_get_handle(&pool, str1, lt_str_length(str1));
        const char *str2 = "on the up and up";
        strpool_handle handle2 = strpool_get_handle(&pool, str2, lt_str_length(str2));
        const char *str3 = "eponymous";
        strpool_handle handle3 = strpool_get_handle(&pool, str3, lt_str_length(str2));

        const char *result_str0 = strpool_get_string(&pool, handle0); 
        assert(lt_str_ncompare(result_str0, str0, lt_str_length(str0)) == 0);

        const char *result_str1 = strpool_get_string(&pool, handle1); 
        assert(lt_str_ncompare(result_str1, str1, lt_str_length(str1)) == 0);

        const char *result_str2 = strpool_get_string(&pool, handle2); 
        assert(lt_str_ncompare(result_str2, str2, lt_str_length(str2)) == 0);

        const char *result_str3 = strpool_get_string(&pool, handle3); 
        assert(lt_str_ncompare(result_str3, str3, lt_str_length(str3)) == 0);

        strpool_calc_string_hash = strpool_calculate_string_hash;
    }

    SIT_TEST(strpool_get_handle_test_insufficient_initial_hashslot_capacity_pass_in_same_string_expect_same_handle)
    {
        strpool_calc_string_hash = strpool_same_hash_stub;

        strpool pool;
        pool.hashslots_load_divider = 3;
        strpool_init(&pool, 64, 4, 10);
        
        const char *str0 = "antithetical";
        strpool_handle handle0 = strpool_get_handle(&pool, str0, lt_str_length(str0));
        const char *str1 = "chicanery";
        strpool_handle handle1 = strpool_get_handle(&pool, str1, lt_str_length(str1));
        const char *str2 = "on the up and up";
        strpool_handle handle2 = strpool_get_handle(&pool, str2, lt_str_length(str2));
        const char *str3 = "on the up and up";
        strpool_handle handle3 = strpool_get_handle(&pool, str3, lt_str_length(str2));

        const char *result_str0 = strpool_get_string(&pool, handle0); 
        assert(lt_str_ncompare(result_str0, str0, lt_str_length(str0)) == 0);

        const char *result_str1 = strpool_get_string(&pool, handle1); 
        assert(lt_str_ncompare(result_str1, str1, lt_str_length(str1)) == 0);

        const char *result_str2 = strpool_get_string(&pool, handle2); 
        assert(lt_str_ncompare(result_str2, str2, lt_str_length(str2)) == 0);

        const char *result_str3 = strpool_get_string(&pool, handle3); 
        assert(lt_str_ncompare(result_str3, str3, lt_str_length(str3)) == 0);

        assert(handle2 == handle3);

        strpool_calc_string_hash = strpool_calculate_string_hash;
    }

    SIT_TEST(strpool_get_handle_test_input_multiple_strings)
    {
        const int n = 4;

		const char *strings[n] = {
			"on the up and up",
			"have a row with someone",
			"hava a bone to pick with someone",
			"sink one's steeth into"
		};

        strpool_handle handles[n];

        strpool pool;
        strpool_init(&pool, 300, 20, 20);

        for (int i = 0; i < n; ++i)
        {
            handles[i] = strpool_get_handle(&pool, strings[i], lt_str_length(strings[i]));
        }

        strpool_string_node *dummy_node = strpool_get_string_node(&pool, pool.dummy_node_offset);
        int32_t node_offset = dummy_node->front_node_offset;
        strpool_string_node *node = strpool_get_string_node(&pool, node_offset);
        for (int i = 0; i < n; ++i)
        {
            const char *teststr = strpool_get_string(&pool, handles[i]);
            assert(lt_str_ncompare(teststr, strings[i], lt_str_length(strings[i])) == 0);
            node_offset += node->size;
            node = strpool_get_string_node(&pool, node_offset);
        }
    }

    SIT_TEST(nw_json_write_int32_test)
    {
        char test_buffer[10];
        size_t buffer_pos = 0;

        nw_json_write_int32(test_buffer, buffer_pos, 0);
        assert(lt_str_ncompare(test_buffer, "0", 1) == 0);
        assert(buffer_pos == 1);
        buffer_pos = 0;

        nw_json_write_int32(test_buffer, buffer_pos, 123);
        assert(lt_str_ncompare(test_buffer, "123", 3) == 0);
        assert(buffer_pos == 3);
        buffer_pos = 0;

        nw_json_write_int32(test_buffer, buffer_pos, -87356);
        assert(lt_str_ncompare(test_buffer, "-87356", 6) == 0);
        assert(buffer_pos == 6);
        buffer_pos = 0;
    }

    struct foo
    {
		int a;
        float next;
		unsigned b;
    };

    SIT_TEST(foo_struct_size_test)
    {
        assert(sizeof(foo) == 12);
    }
}
