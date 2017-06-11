/***

todo
[ ] : to start  [x] : complete  [i] : in progress  [w] : won't do

[i] Write command line loop.
[ ] Revise strpool_string_node structure and the way of finding next free node.
[ ] Address reference counting issue of strpool_handle.
[ ] Add memory footprint metrics.
[ ] Make a simple stupid unit test framework that can save me from manually 
    calling every test function.
[i] Write unit tests for strpool.
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

/*==================
    Helper Functions
==================*/

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
 * otherwise return 0. 
 *
 * Examples: ("aabb", "aabbc", 4) returns 0
 *           ("aabb", "aabbc", 5) returns negative integer
 *           ("aAbb", "aabb", 4) returns negative integer
 */
int lt_str_ncompare(const char *str0, const char *str1, size_t count)
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


/*================
    String Pool 
================*/

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
 * A strpool_string_node is stored in front of every string.
 */
struct strpool_string_node
{
    // memory offset of strpool_string_node in strpool.string_block 
    int32_t prev_node_offset;
    int32_t next_node_offset;

    // the memory offset of the string node that's physically in front of this 
    // node in memory
    int32_t front_node_offset;

    // size = sizeof(strpool_string_node) + string_length + sizeof('\0') + alignment_padding
    int32_t size; 

    // string_length == 0 means it's a free node
    int32_t string_length;
};

#define STRPOOL_STRING_BLOCK_MIN_SIZE next_pow2(sizeof(strpool_string_node) + 8 + 1)

#define STRPOOL_DUMMY_NODE_SENTINEL 0x001df001

struct strpool
{
    strpool_hashslot *hashslots;
    strpool_entry *entries;

    // Memory block storing all strings. Each string must be appended with '\0', 
    // and prepended with a strpool_string_node.
    char *string_block;
    int32_t string_block_size;

    // dummy node serves as head and tail for a circular linked list, it's always 0
    int32_t dummy_node_offset;

    // dummy free entry, always 0
    int32_t dummy_free_entry_index;

    int32_t hashslots_capacity;
    int32_t entries_capacity;
    int32_t hashslots_count;
    int32_t entries_count;

    ~strpool()
    {
        if (hashslots != 0)
        {
            free(hashslots);
        }

        if (entries != 0)
        {
            free(entries);
        }

        if (string_block != 0)
        {
            free(string_block);
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
 * Insert insertee_node after first_node
 */
void strpool_insert_string_node(strpool *pool, int32_t first_node_offset, int32_t insertee_node_offset)
{
    strpool_string_node *first_node = strpool_get_string_node(pool, first_node_offset);
    strpool_string_node *second_node = strpool_get_string_node(pool, first_node->next_node_offset);
    strpool_string_node *insertee_node = strpool_get_string_node(pool, insertee_node_offset);

	// insert insertee_node in between first_node and second_node
    insertee_node->next_node_offset = first_node->next_node_offset;
    second_node->prev_node_offset = insertee_node_offset;
    first_node->next_node_offset = insertee_node_offset;
    insertee_node->prev_node_offset = first_node_offset;
}

void strpool_insert_free_node(strpool *pool, strpool_string_node *free_node)
{
    strpool_string_node *dummy_node = strpool_get_string_node(pool, pool->dummy_node_offset);
    strpool_string_node *node = dummy_node;
    strpool_string_node *next_node = strpool_get_string_node(pool, node->next_node_offset);

    // Insert the free node in descending order regarding size. This makes the 
    // memory less fragmented but the insertion operation lower.
    while (next_node != dummy_node && 
           next_node->string_length == 0 && 
           next_node->size < free_node->size)
    {
        node = next_node;
        next_node = strpool_get_string_node(pool, node->next_node_offset);
    }

    int32_t node_offset = (int32_t)((char *)node - pool->string_block);
    int32_t free_node_offset = (int32_t)((char *)free_node - pool->string_block);
    strpool_insert_string_node(pool, node_offset, free_node_offset);
}

int32_t strpool_init(strpool *pool, int32_t string_block_size, int32_t hashslot_capacity, int32_t entry_capacity)
{
    string_block_size = memory_align(string_block_size, STRPOOL_STRING_BLOCK_MIN_SIZE);
    pool->string_block = (char *)malloc(string_block_size);
    assert(pool->string_block);
    pool->string_block_size = string_block_size;
    memset(pool->string_block, 0, pool->string_block_size);

    pool->dummy_node_offset = 0;
    strpool_string_node *dummy_node = strpool_get_string_node(pool, pool->dummy_node_offset);
    dummy_node->size = STRPOOL_STRING_BLOCK_MIN_SIZE;
    dummy_node->string_length = STRPOOL_DUMMY_NODE_SENTINEL;

    int32_t first_node_offset = STRPOOL_STRING_BLOCK_MIN_SIZE;
    int32_t first_node_size = pool->string_block_size - STRPOOL_STRING_BLOCK_MIN_SIZE;
    strpool_string_node *first_node = strpool_get_string_node(pool, first_node_offset);
    first_node->size = first_node_size;
    first_node->string_length = 0;

    first_node->prev_node_offset = pool->dummy_node_offset;
    first_node->next_node_offset = pool->dummy_node_offset;
	dummy_node->prev_node_offset = first_node_offset;
	dummy_node->next_node_offset = first_node_offset;

    int32_t hashslot_buffer_size = hashslot_capacity * sizeof(strpool_hashslot);
    pool->hashslots = (strpool_hashslot*)malloc(hashslot_buffer_size);
    assert(pool->hashslots);
    pool->hashslots_capacity = hashslot_capacity;
    pool->hashslots_count = 0;
    memset(pool->hashslots, 0, hashslot_buffer_size);

    int32_t entry_buffer_size = entry_capacity * sizeof(strpool_entry);
    pool->entries = (strpool_entry *)malloc(entry_buffer_size);
    assert(pool->entries);
    pool->entries_capacity = entry_capacity;
    pool->entries_count = 0;
    memset(pool->entries, 0, entry_buffer_size);

    pool->dummy_free_entry_index = 0;
    strpool_entry &dummy_free_entry = pool->entries[pool->dummy_free_entry_index];
    dummy_free_entry.prev_free_entry_index = pool->dummy_free_entry_index;
    dummy_free_entry.next_free_entry_index = pool->dummy_free_entry_index;
    pool->entries_count++;

    return 1;
}

int32_t strpool_store_string(strpool *pool, const char *string, int str_length)
{
    int32_t string_data_offset = -1;

    strpool_string_node *dummy_node = strpool_get_string_node(pool, pool->dummy_node_offset);
    int32_t node_offset = dummy_node->next_node_offset;
    while (node_offset != pool->dummy_node_offset)
    {
        strpool_string_node *node = strpool_get_string_node(pool, node_offset);

        if (node->string_length == 0)
        {
			int aliged_current_node_size = memory_align(sizeof(strpool_string_node) + str_length + sizeof('\0'), 8);
			if (node->size >= aliged_current_node_size)
			{
                string_data_offset = node_offset + sizeof(strpool_string_node);
				char *string_data = (char *)node + sizeof(strpool_string_node);
                // memcpy requires restrict pointer, we assume it's safe here.
				memcpy(string_data, string, str_length);
				string_data[str_length] = '\0';
				node->string_length = str_length;
				
				int size_left = node->size - aliged_current_node_size;
				int min_size = STRPOOL_STRING_BLOCK_MIN_SIZE;
				if (size_left >= min_size)
				{
					node->size = aliged_current_node_size;

                    int32_t next_free_node_offset = node_offset + aliged_current_node_size;
					strpool_string_node *next_free_node = strpool_get_string_node(pool, next_free_node_offset);
					next_free_node->size = size_left;
					next_free_node->string_length = 0;

                    strpool_insert_string_node(pool, pool->dummy_node_offset, next_free_node_offset);
				}
				break;
			}
        }
        node_offset = node->next_node_offset;
    }

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
    uint32_t base_slot_index = current_hash % (uint32_t)pool->hashslots_capacity;
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

        uint32_t slot_hash_base_index = slot_hash % (uint32_t)pool->hashslots_capacity;
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

        slot_index = (slot_index + 1) % (uint32_t)pool->hashslots_capacity;
    }

    /*
     * Add an entry for the new input_string.
     */

    if (pool->entries_count >= pool->hashslots_capacity - pool->hashslots_capacity / 3)
    {
        /* Expand hash slots. */

        int32_t old_hash_slots_capacity = pool->hashslots_capacity;
        strpool_hashslot *old_hash_slots = pool->hashslots;
        pool->hashslots_capacity = old_hash_slots_capacity * 2;
        pool->hashslots = (strpool_hashslot *)malloc(pool->hashslots_capacity * sizeof(*pool->hashslots));
        assert(pool->hashslots);
        memset(pool->hashslots, 0, pool->hashslots_capacity * sizeof(*pool->hashslots));

        for (int i = 0; i < old_hash_slots_capacity; ++i)
        {
            uint32_t old_slot_string_hash = old_hash_slots[i].string_hash;
            if (old_slot_string_hash)
            {
                int32_t base_slot_index = old_slot_string_hash % pool->hashslots_capacity;
                int32_t slot_index = base_slot_index;
                while (pool->hashslots[slot_index].string_hash)
                {
                    slot_index = (slot_index + 1) % pool->hashslots_capacity;
                }
                pool->hashslots[slot_index].string_hash = old_slot_string_hash;
                pool->hashslots[slot_index].entry_index = old_hash_slots[i].entry_index;
                pool->hashslots[slot_index].base_count++;
                pool->entries[old_hash_slots[i].entry_index].hashslot = slot_index;
            }
        }

        free(old_hash_slots);
    }

    while (pool->hashslots[first_free_slot_index].string_hash != 0)
    {
        // If we couldn't find a free slot in between slots tested above, continue searching.
        first_free_slot_index = (first_free_slot_index + 1) % pool->hashslots_capacity;
    }

    int32_t new_entry_index = 0;
    if (pool->entries_count >= pool->entries_capacity)
    {
        strpool_entry &dummy_free_entry = pool->entries[pool->dummy_free_entry_index];
        if (dummy_free_entry.next_free_entry_index == pool->dummy_free_entry_index)
        {
            /* Expand entry array. */

            int32_t old_entries_capacity = pool->entries_capacity;
            pool->entries_capacity = old_entries_capacity * 2;
            strpool_entry *new_entry_buffer = (strpool_entry *)malloc(pool->entries_capacity * sizeof(*pool->entries));
            assert(new_entry_buffer);
            memcpy(new_entry_buffer, pool->entries, old_entries_capacity * sizeof(*pool->entries));
            free(pool->entries);
            pool->entries = new_entry_buffer;

            new_entry_index = pool->entries_count;
            pool->entries_count++;
        }
        else
        {
            new_entry_index = dummy_free_entry.next_free_entry_index;

            // delete new_entry_index from free entry list
            strpool_entry &new_entry = pool->entries[new_entry_index];
            dummy_free_entry.next_free_entry_index = new_entry.next_free_entry_index;
            strpool_entry &next_free_entry = pool->entries[new_entry.next_free_entry_index];
            next_free_entry.prev_free_entry_index = pool->dummy_free_entry_index;
        }
    }
    else
    {
        new_entry_index = pool->entries_count;
        pool->entries_count++;
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
    if (string_data_offset == -1)
    {
        /* Expand string block and then try again.*/

        int new_string_block_size = memory_align(pool->string_block_size * 2, STRPOOL_STRING_BLOCK_MIN_SIZE);
        char *new_string_block = (char *)malloc(new_string_block_size);
        memcpy(new_string_block, pool->string_block, pool->string_block_size);

        int32_t next_free_node_offset = pool->string_block_size;
        strpool_insert_string_node(pool, pool->dummy_node_offset, next_free_node_offset);
        strpool_string_node *next_free_node = strpool_get_string_node(pool, next_free_node_offset);
        next_free_node->size = new_string_block_size - pool->string_block_size;
        next_free_node->string_length = 0;

        free(pool->string_block);
        pool->string_block = new_string_block;
        pool->string_block_size = new_string_block_size;

		string_data_offset = strpool_store_string(pool, input_string, input_str_length);
		assert(string_data_offset > 0);
    }
    
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

    strpool_string_node *node = (strpool_string_node *)(pool->string_block + entry.string_data_offset - sizeof(strpool_string_node));

    if (node->front_node_offset != pool->dummy_node_offset)
    {
        strpool_string_node *front_node = strpool_get_string_node(pool, node->front_node_offset);
        if (front_node->string_length == 0)
        {
            /* Conjoin this node and the free one in front. */

            strpool_string_node *prev_node = strpool_get_string_node(pool, node->prev_node_offset);
            strpool_string_node *next_node = strpool_get_string_node(pool, node->next_node_offset);
            prev_node->next_node_offset = node->next_node_offset;
            next_node->prev_node_offset = node->prev_node_offset;

            front_node->size = front_node->size + node->size;
            node = front_node;
        }
    }

    if ((char *)node + node->size < pool->string_block)
    {
        int32_t node_offset = (int32_t)((char *)node - pool->string_block + node->size);
        strpool_string_node *back_node = strpool_get_string_node(pool, node_offset);
        if (back_node->string_length == 0)
        {
            /* Combine with the free one in back */

            strpool_string_node *prev_node = strpool_get_string_node(pool, back_node->prev_node_offset);
            strpool_string_node *next_node = strpool_get_string_node(pool, back_node->next_node_offset);
            prev_node->next_node_offset = back_node->next_node_offset;
            next_node->prev_node_offset = back_node->prev_node_offset;

            node->size = node->size + back_node->size;
        }
    }

    strpool_insert_free_node(pool, node);

    /* Recycle entry and hashslot */

    int32_t base_slot_index = entry.string_hash % pool->hashslots_capacity;
    pool->hashslots[base_slot_index].base_count--;
    pool->hashslots[entry.hashslot].string_hash = 0;

    if (handle.entry_index == pool->entries_count - 1)
    {
        pool->entries_count--;
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
    }

    return 0;
}

const char *strpool_get_string(strpool *pool, strpool_handle handle)
{
    const strpool_entry &entry = pool->entries[handle.entry_index];
    const char *result = (const char *)(pool->string_block + entry.string_data_offset);
	return result;
}


/*====================
    Networds app
====================*/

struct netword_t
{
    strpool_handle this_word;
    int related_words_count;
    strpool_handle *related_words;
    int related_words_capacity;
    int visits;
};

struct networdpool_t
{
    netword_t *words = 0;
    int words_count = 0;
    int pool_capacity = 0;
};

netword_t *nw_make_word(networdpool_t *wordspool, const char *word, int word_length, strpool *stringpool)
{
    if (wordspool->words_count > wordspool->pool_capacity)
    {
        // TODO: inscreen wordspool capacity
    }
    netword_t *result = &wordspool->words[wordspool->words_count++];
    result->this_word = strpool_get_handle(stringpool, word, word_length);

    result->related_words_count = 0;
    result->related_words_capacity = 3;
    result->related_words = (strpool_handle *)malloc(result->related_words_capacity * sizeof(strpool_handle));

    result->visits = 1;
    return result;
}

void nw_add_related_word(netword_t *word, const char *related_word, int related_word_length, strpool *stringpool)
{
    if (word->related_words_count > word->related_words_capacity)
    {
        // TODO: inscrease related words capacity
    }
    word->related_words[word->related_words_count++] = strpool_get_handle(stringpool, related_word, related_word_length);
}

int nw_add_related_words(netword_t *word, char *new_relative)
{
    //int new_relative_length = lt_str_length(new_relative);

    //if (word->relatives == nullptr)
    //{
    //    word->relatives = (char *)malloc(new_relative_length + 1);
    //    lt_str_ncopy(word->relatives, new_relative_length + 1, new_relative);
    //    word->relative_num = 1;
    //}
    //else
    //{
    //    int old_length = lt_str_length(word->relatives);
    //    int size = old_length + 1 + new_relative_length + 1; // 1 for space, 1 for '\0'
    //    char *new_buffer = (char *)realloc(word->relatives, size);
    //    if (new_buffer)
    //    {
    //        word->relatives = new_buffer;
    //        new_buffer = nullptr;
    //        *(word->relatives + old_length) = ' ';
    //        lt_str_ncopy(word->relatives + old_length + 1, new_relative_length + 1, new_relative);
    //    }
    //    else
    //    {
    //        // TODO lw: log
    //        return -1;
    //    }
    //}

    return 0;
}

/*========================
    Json Reader/Writer
========================*/

const char *nw_json_error(const char *errmsg)
{
    static const size_t error_msg_size = 256;
    static char error_msg[error_msg_size];
    lt_str_ncopy(error_msg, error_msg_size, errmsg);
    assert(false);
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
        return 0;
    }

    // the position of the leading bit represents the collection depth
    uint32_t collection_depth = 0;
    // each bit represents the collection type at the depth of the bit position
    uint32_t collection_types[32];

    size_t json_str_pos = 0;
    char next_char = nw_next_nonwhitespace(json_str, json_str_pos);
    if (next_char != '[')
    {
        nw_json_error("The first non-whilespace character has to be \'[\'!");
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
                }
                goto parsing_next_key_pair;
            } break;

            case '}':
            {
                if (collection_types[collection_depth - 1] != json_collection_type_object)
                {
                    nw_json_error("Collection type mismatch!");
                }
                collection_depth -= 1;
                if (current_word == 0)
                {
                    nw_json_error("Currently being parsed networds is null!");
                }
                current_word = 0;
                goto parsing_next_character;
            } break;

            case ']':
            {
                if (collection_types[collection_depth - 1] != json_collection_type_array)
                {
                    nw_json_error("Collection type mismatch!");
                }
                collection_depth -= 1;
                if (collection_depth != 0)
                {
                    nw_json_error("Collection unclosed!");
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
            } break;
        }

        parsing_next_key_pair:

        next_char = nw_next_nonwhitespace(json_str, json_str_pos);
        if (next_char != '\"')
        {
            nw_json_error("Non-conforming JSON file, expecting \'\"\'!");
        }

        if (lt_str_ncompare(json_str + json_str_pos, "word\"", 5) == 0)
        {
            json_str_pos += 5;
            next_char = nw_next_nonwhitespace(json_str, json_str_pos);
            if (next_char != ':')
            {
                nw_json_error("Non-conforming JSON file, expecting \':\'!");
            }
            next_char = nw_next_nonwhitespace(json_str, json_str_pos);
            if (next_char != '\"')
            {
                nw_json_error("Non-conforming JSON file, expecting \'\"\'!");
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
            }
            next_char = nw_next_nonwhitespace(json_str, json_str_pos);
            if (next_char != '[')
            {
                nw_json_error("Expecting \'[\' for an array of related words!");
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
            }
            if (collection_types[collection_depth - 1] != json_collection_type_array)
            {
                nw_json_error("Collection type mismatch!");
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
            }
            int32_t visitsn = nw_json_skip_int32(json_str, json_str_pos);
            current_word->visits = visitsn;
            goto parsing_next_character;
        }
        else
        {
            nw_json_error("Unrecognized key!");
        }

        parsing_next_character:

		next_char = nw_next_nonwhitespace(json_str, json_str_pos);
    }

    parsing_finished:

	return 0;
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

void nw_json_write(networdpool_t *wordspool, char *json_buffer, size_t json_buffer_size, strpool *stringpool)
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

    assert(json_buffer_pos < json_buffer_size);
}


/*============================
    Command Line Loop
============================*/

void nw_skip_whitespace(const char *cmdline, size_t &cmdline_pos)
{
    char c = *(cmdline + cmdline_pos);
    while (c == ' ' || c == '\n' || c == '\t' || c == '\r' || c == '\v')
    {
        c = *(cmdline + (++cmdline_pos));
    }
    return;
}

struct nw_cmdl_tokens
{
    static const int MaxTokenNum = 128;
    int token_num = 0;
    int token_start_positions[MaxTokenNum];
    int token_end_positions[MaxTokenNum];
};

enum nw_cmd_e
{
    cmd_unrecognized = 0,
    cmd_exit = 1,
    cmd_new = 2,
    cmd_add = 3,
    cmd_num = 4,
};

nw_cmd_e nw_cmdl_tokenize(const char *cmdline, int cmdline_length, nw_cmdl_tokens *tokens)
{
    nw_cmd_e nw_cmd = nw_cmd_e::cmd_unrecognized;
	size_t cmdline_pos = 0;
    if (lt_str_ncompare(cmdline, "exit", 4) == 0)
    {
        return nw_cmd_e::cmd_exit;
    }
    else if (lt_str_ncompare(cmdline, "nw ", 3) != 0)
    {
        return nw_cmd_e::cmd_unrecognized;
    }
    cmdline_pos += 3;
    nw_skip_whitespace(cmdline, cmdline_pos);
    if (lt_str_ncompare(cmdline + cmdline_pos, "new ", 4) == 0)
    {
        nw_cmd = nw_cmd_e::cmd_new;
        cmdline_pos += 4;
    }
    else if (lt_str_ncompare(cmdline + cmdline_pos, "add ", 4) == 0)
    {
        nw_cmd = nw_cmd_e::cmd_add;
        cmdline_pos += 4;
    }
    else if (lt_str_ncompare(cmdline + cmdline_pos, "num ", 4) == 0)
    {
        nw_cmd = nw_cmd_e::cmd_num;
        cmdline_pos += 4;
    }
    else
    {
        return nw_cmd_e::cmd_unrecognized;
    }
    while(cmdline_pos < cmdline_length)
    {
        nw_skip_whitespace(cmdline, cmdline_pos);
        tokens->token_start_positions[tokens->token_num] = (int)cmdline_pos - 1;
        while (*(cmdline + cmdline_pos) != ',' && 
               *(cmdline + cmdline_pos) != '\n' &&
               cmdline_pos < cmdline_length)
        {
            cmdline_pos++;
        }
        tokens->token_end_positions[tokens->token_num] = (int)cmdline_pos - 1;
        // trim whitespaces at end
        while (*(cmdline + tokens->token_end_positions[tokens->token_num]) == ' ' ||
               *(cmdline + tokens->token_end_positions[tokens->token_num]) == '\t' ||
               *(cmdline + tokens->token_end_positions[tokens->token_num]) == '\r')
        {
            tokens->token_end_positions[tokens->token_num]--;
        }
        tokens->token_num++;
    }
	return nw_cmd;
}

/**
 * Read all characters from \ref stream until it meets '\n', '\0' or EOF, or the 
 * amount of characters read equals \ref max_line_length.
 * This function doesn't guarantee \ref line will be null-terminated.
 */
int nw_cmd_readline(FILE *stream, char *line, int max_line_length)
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

void nw_cmdl_run()
{
    networdpool_t networdspool;
    networdspool.pool_capacity = 

    FILE *netword_json_file = 0;
    fopen_s(&netword_json_file, "networds.json", "r");
    if (netword_json_file)
    {

    }


    nw_cmdl_tokens cmdl_tokens;
    const int cmdline_max_length = 1024;
    char cmdline[cmdline_max_length];
    char cmdline_length = 0;

    while (1)
    {
        cmdline_length = nw_cmd_readline(stdin, cmdline, cmdline_max_length);
        nw_cmd_e nw_cmd = nw_cmdl_tokenize(cmdline, cmdline_length, &cmdl_tokens);

        switch(nw_cmd)
        {
            case nw_cmd_e::cmd_exit:
            {
                return;
            } break;

            case nw_cmd_e::cmd_new:
            {
                printf("nw new ...\n");
            } break;

            case nw_cmd_e::cmd_add:
            {
                printf("nw add ...\n");
            } break;

            case nw_cmd_e::cmd_num:
            {
                printf("nw num ...\n");
            } break;

            case nw_cmd_e::cmd_unrecognized:
            {
                printf("unrecognized command.\n");
            } break;
        }

        cmdl_tokens.token_num = 0;
    }
}


/*===============
    Unit Tests
===============*/

namespace NetwordsTests
{
    void next_pow2_input_zero_return_one()
    {
        uint32_t result = next_pow2(0);
        assert(result == 1);
    }

    void memory_align_input_normal()
    {
        uint32_t result = memory_align(0x000f, 8);
        assert(result == 0x0010);
        result = memory_align(0x0008, 8);
        assert(result == 0x0008);
    }

    void lt_str_ncompare_input_various()
    {
        assert(lt_str_ncompare("aabb", "aabbc", 4) == 0);
        assert(lt_str_ncompare("aabb", "aabbc", 5) < 0);
        assert(lt_str_ncompare("aAbb", "aabb", 4) < 0);
        assert(lt_str_ncompare("aabc", "aabb", 4) > 0);
    }

    void strpool_init_input_normal_set_dummy_node()
    {
        const int32_t pool_string_block_size = 100;

        strpool pool;
        strpool_init(&pool, pool_string_block_size, 20, 20);
        assert(pool.dummy_node_offset == 0);

        strpool_string_node *dummy_node = strpool_get_string_node(&pool, pool.dummy_node_offset);
        assert(dummy_node->string_length == STRPOOL_DUMMY_NODE_SENTINEL);

        strpool_string_node *next_free_node = strpool_get_string_node(&pool, dummy_node->next_node_offset);
        assert(next_free_node->string_length == 0);
        assert(next_free_node->next_node_offset == pool.dummy_node_offset);
        assert(next_free_node->prev_node_offset == pool.dummy_node_offset);

        assert(dummy_node->size + next_free_node->size == pool.string_block_size);
    }

    void strpool_get_handle_input_normal_return_normal()
    {
        const char *test_str0 = "good stuff";
        strpool pool;
        strpool_init(&pool, 100, 20, 20);

        strpool_handle handle = strpool_get_handle(&pool, test_str0, lt_str_length(test_str0));
        const char *result_str0 = strpool_get_string(&pool, handle);

        assert(lt_str_ncompare(test_str0, result_str0, lt_str_length(result_str0)) == 0);
    }

    void strpool_get_handle_input_existing_string_return_normal()
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

    STRPOOL_STRING_HASH_F(strpool_same_hash_stub)
    {
        return 1771;
    }

    void strpool_get_handle_input_existing_string_same_hash_return_normal()
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

    void strpool_get_handle_input_multiple_strings_return_normal()
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

        strpool_string_node *node = strpool_get_string_node(&pool, pool.dummy_node_offset);
        for (int i = 0; i < n; ++i)
        {
            const char *teststr = pool.string_block + node->prev_node_offset + sizeof(strpool_string_node);
            assert(lt_str_ncompare(teststr, strings[i], lt_str_length(strings[i])) == 0);
            node = strpool_get_string_node(&pool, node->prev_node_offset);
        }
    }

    void nw_json_write_int32_test()
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

    void run_tests()
    {
		next_pow2_input_zero_return_one();
		memory_align_input_normal();
        lt_str_ncompare_input_various();
        nw_json_write_int32_test();

        strpool_init_input_normal_set_dummy_node();
        strpool_get_handle_input_normal_return_normal();
        strpool_get_handle_input_existing_string_return_normal();
        strpool_get_handle_input_multiple_strings_return_normal();
        strpool_get_handle_input_existing_string_same_hash_return_normal();

        // printf("size of foo: %d", (int32_t)sizeof(foo));
    }
}
