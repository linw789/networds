/***

todo lw:

[x] Finish strpool_discard_handle function, take into account of ref_count
[x] Fix all lt_* functions
[ ] Upload this project to Github
[ ] Write unit tests for strpool

***/


#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h> // memcmp, memcpy

#define ASSERT(x) if (!(x)) { abort(); }

/*==================
    Helper functions
==================*/

/**
 * Compute the smallest power of 2 that's larger than or equal to x.
 */
uint32_t next_pow2(uint32_t x)
{
    ASSERT(x < 0x80000001);
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
 * Could virtual memory address be larger than 2GB?
 * @param a The alignment must be power of 2
 */
uint32_t memory_align(uint32_t memory, uint32_t a)
{
    ASSERT(a > 0)
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
    int count = 0;
    while (*(str + count) != '\0')
    {
        count++;
    }
    return count;
}

/**
 * Copy the string from source buffer to destination buffer. If the '\0' is met 
 * before the specified number of characters have been copied, terminate the 
 * copy process and append '\0' to the destination buffer.
 *
 * @param dest The destination buffer to store copied string.
 * @param dest_size The number of characters the destination buffer can hold.
 * @param src The source buffer to copy the string from.
 * @param src_size The number of character to copy from source buffer.
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


/*================
    String Pool 
================*/

struct strpool_hashslot
{
    uint32_t string_hash;
    int entry_index;
    // the number of times a string is originally hashed at this slot
    int base_count;
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

        int32_t prev_free_entry_index;
    };

    union
    {
        int32_t hashslot;
        int32_t next_free_entry_index;
    };

    // this is a free entry if ref_count is 0
    uint32_t ref_count;
};

struct strpool_handle
{
    int32_t entry_index;
};

/**
 * This node is stored in front of every string.
 */
struct strpool_string_node
{
    // memory offset of strpoo_string_node in strpool.string_block
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
    // and prepended with a uint32_t hash and a uint32_t string length.
    char *string_block;
    int32_t string_block_size;

    // dummy node servers as head and tail for a circular linked list, it's always 0
    int32_t dummy_node_offset;

    // dummy free entry, always 0
    int32_t dummy_free_entry_index;

    int32_t hashslots_capacity;
    int32_t entries_capacity;
    int32_t hashslots_count;
    int32_t entries_count;
};

uint32_t strpool_calculate_string_hash(const char* string, int32_t length)
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

// String hash function can be replaces for unit testing purpose.
#define STRPOOL_CALCULATE_STRING_HASH strpool_calculate_string_hash

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
    ASSERT(pool->string_block);
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
    ASSERT(pool->hashslots);
    pool->hashslots_capacity = hashslot_capacity;
    pool->hashslots_count = 0;
    memset(pool->hashslots, 0, hashslot_buffer_size);

    int32_t entry_buffer_size = entry_capacity * sizeof(strpool_entry);
    pool->entries = (strpool_entry *)malloc(entry_buffer_size);
    ASSERT(pool->entries);
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

int32_t strpool_deinit(strpool *pool)
{
    ASSERT(pool->hashslots != 0);
    free(pool->hashslots);

    ASSERT(pool->entries != 0);
    free(pool->entries);

    ASSERT(pool->string_block != 0);
    free(pool->string_block);

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
 */
strpool_handle strpool_get_handle(strpool *pool, const char *input_string, int input_str_length)
{
    uint32_t current_hash = STRPOOL_CALCULATE_STRING_HASH(input_string, input_str_length);
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

        // Record the first free hash slot to right of the base slot.
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
            if (memcmp(string_data + sizeof(strpool_string_node), input_string, input_str_length) == 0)
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
        ASSERT(pool->hashslots);
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
            ASSERT(new_entry_buffer);
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
		ASSERT(string_data_offset > 0);
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

const char *strpool_get_string(strpool_handle handle)
{
	return 0;
}

/*=====================
    Networds app
=====================*/

struct netword
{
    char *wordkey = nullptr; // word or phrase
    char *relatives = nullptr; // an array of space separated related words in a continuous memory.
    int relative_num = 0; // number of related words
    int visit_num = 0; // number of times this word is looked up
};

netword nw_make(const char *word)
{
    netword result;
    result.visit_num = 1;

    int word_length = lt_str_length(word);
    result.wordkey = (char *)malloc(word_length + 1);
    lt_str_ncopy(result.wordkey, word_length + 1, word);

    return result;
}

int nw_add_related_words(netword *word, char *new_relative)
{
    int new_relative_length = lt_str_length(new_relative);

    if (word->relatives == nullptr)
    {
        word->relatives = (char *)malloc(new_relative_length + 1);
        lt_str_ncopy(word->relatives, new_relative_length + 1, new_relative);
        word->relative_num = 1;
    }
    else
    {
        int old_length = lt_str_length(word->relatives);
        int size = old_length + 1 + new_relative_length + 1; // 1 for space, 1 for '\0'
        char *new_buffer = (char *)realloc(word->relatives, size);
        if (new_buffer)
        {
            word->relatives = new_buffer;
            new_buffer = nullptr;
            *(word->relatives + old_length) = ' ';
            lt_str_ncopy(word->relatives + old_length + 1, new_relative_length + 1, new_relative);
        }
        else
        {
            // TODO lw: log
            return -1;
        }
    }

    return 0;
}

int nw_output_json(netword *entries, int count)
{
    int total_buffer_size = 0;
    for (int i = 0; i < count; ++i)
    {
        netword *w = entries + i;
        total_buffer_size += lt_str_length(w->wordkey);
        total_buffer_size += lt_str_length(w->relatives);
        total_buffer_size += w->relative_num * 2;
        total_buffer_size += 100; // boilerplate
    }

    char *buffer = (char *)malloc(total_buffer_size + 1);
    int buffer_pos = 0;

    int copied_size = lt_str_ncopy(buffer + buffer_pos, total_buffer_size - buffer_pos, "{\n\n\"networds\" : \n");
    buffer_pos += copied_size;

    for (int i = 0; i < count; ++i)
    {
        copied_size = lt_str_ncopy(buffer + buffer_pos, total_buffer_size - buffer_pos, "    {\n        \"wkey\" : ");
        buffer_pos += copied_size; 

    }

    copied_size = lt_str_ncopy(buffer + buffer_pos, total_buffer_size, "\n]\n\n}");
    buffer_pos += copied_size;

    return 0;
}

/*===============
    Unit Tests
===============*/

namespace NetwordsTests
{
    void next_pow2_input_zero_return_one()
    {
        uint32_t result = next_pow2(0);
        ASSERT(result == 1);
    }

    void memory_align_input_normal()
    {
        uint32_t result = memory_align(0x000f, 8);
        ASSERT(result == 0x0010);
        result = memory_align(0x0008, 8);
        ASSERT(result == 0x0008);
    }

    void strpool_init_input_normal_set_dummy_node()
    {
        const int32_t pool_string_block_size = 100;

        strpool pool;
        strpool_init(&pool, pool_string_block_size, 20, 20);
        ASSERT(pool.dummy_node_offset == 0);

        strpool_string_node *dummy_node = strpool_get_string_node(&pool, pool.dummy_node_offset);
        ASSERT(dummy_node->string_length == STRPOOL_DUMMY_NODE_SENTINEL);

        strpool_string_node *next_free_node = strpool_get_string_node(&pool, dummy_node->next_node_offset);
        ASSERT(next_free_node->string_length == 0);
        ASSERT(next_free_node->next_node_offset == pool.dummy_node_offset);
        ASSERT(next_free_node->prev_node_offset == pool.dummy_node_offset);

        ASSERT(dummy_node->size + next_free_node->size == pool.string_block_size);

        strpool_deinit(&pool);
    }

    void strpool_get_handle_input()
    {

    }

    void run_tests()
    {
		next_pow2_input_zero_return_one();
		memory_align_input_normal();

        strpool_init_input_normal_set_dummy_node();
    }
}