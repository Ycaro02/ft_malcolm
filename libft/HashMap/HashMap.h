/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   HashMap.h                                          :+:      :+:    :+:   */
/*   By: nfour <nfour@student.42angouleme.fr>       +#+  +:+       +#+        */
/*   Created: 2024/04/29 19:35:19 by nfour             #+#    #+#             */
/*   Updated: 2025/06/02 22:05:03 by nfour            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef HEADER_HASHMAP_H
#define HEADER_HASHMAP_H

#include "../libft.h"
#include "../thread/pthread_utils.h"

/**
 * @file HashMap.h
 * @brief Generic, thread-safe hash map implementation in C.
 *
 * This hash map supports arbitrary key and value types via user-provided
 * hash, copy, compare, and free functions. It is designed for efficient
 * insertion, lookup, update, and removal of key-value pairs, with automatic
 * resizing and collision handling via separate chaining (linked lists).
 *
 * Features:
 *  - Store any type of key or value (void*).
 *  - User must provide functions for key hashing, key copying, key freeing,
 *    and key comparison, as well as value freeing.
 *  - Thread-safe via internal mutex.
 *  - Automatic resizing (rehashing) when needed.
 *  - Iterator API for traversing all entries.
 *  - Constant average-time complexity for insert, lookup, and remove.
 *
 * Usage notes:
 *  - Keys are internally allocated by the hashmap using the user-provided copy_key_data function.
 *    Therefore, keys passed to hashmap_set_entry do **not** need to be heap-allocated by the user.
 *  - Values must be heap-allocated they are copied by pointer assignment.
 *  - The hash map takes ownership of keys and values and will free them
 *    using the provided callbacks.
 *  - The user is responsible for providing correct and compatible callbacks.
 */

/* ======================= STRUCTURES ======================= */

/**
 * @struct HashMap_entry
 * @brief Represents a single key-value pair in the hash map.
 *
 * - key_data: Pointer to the original key data (heap-allocated).
 * - key:      Hash value of the key (u64).
 * - value:    Pointer to the value (heap-allocated if needed).
 */
typedef struct s_hashmap_entry {
    void 	    *key_data;	/* Original key data (heap-allocated) */
    u64			key;		/* Hash value of the key */
    void		*value;		/* Associated value */
} HashMap_entry;


/* ======================= CALLBACK ======================= */

/**
 * - free_obj: Callback to free a value.
 *      This function is called by the hashmap whenever a value needs to be destroyed,
 *      such as when an entry is removed or the hashmap is destroyed. It must correctly
 *      free all memory associated with the value pointer. The user must provide a function
 *      compatible with the value type stored in the map.
 *
 * - free_key_data: Callback to free a key.
 *      This function is called by the hashmap to release memory allocated for a key.
 *      It is used internally when an entry is removed or the hashmap is destroyed.
 *      The user must provide a function that frees all memory associated with the key pointer.
 *
 * - copy_key_data: Callback to copy a key (deep copy).
 *      This function is called by the hashmap to create an independent copy of a key
 *      when inserting a new entry. It must perform a deep copy of the key data and
 *      return a pointer to a newly heap-allocated key. The hashmap will take ownership
 *      of this copy and will free it using free_key_data. The user must ensure that
 *      the returned pointer is valid and independent from the original.
 *
 * - hash: Callback to hash a key.
 *      This function computes a 64-bit hash value from the key data. The quality of
 *      this function directly impacts the distribution of entries in the hashmap and
 *      the likelihood of collisions. The user should provide a hash function that
 *      distributes keys uniformly and minimizes collisions for the expected key set.
 *
 * - key_cmp: Callback to compare two keys.
 *      This function compares two key pointers for equality. It must return 1 if the
 *      keys are considered equal, and 0 otherwise. The hashmap uses this function to
 *      identify matching keys during lookup, insertion, and removal. The comparison
 *      must be consistent with the hash function: if key_cmp(a, b) returns 1, then
 *      hash(a) and hash(b) must return the same value.
 */

/**
 * @struct HashMap_callbacks
 * @brief Callbacks for key/value operations in the hash map.
 * 
 * - free_obj:          Callback to free a value.
 * - free_key_data:    Callback to free a key.
 * - copy_key_data:     Callback to copy a key (deep copy).
 * - hash:             Callback to hash a key.
 * - key_cmp:         Callback to compare two keys.
 */

 typedef struct s_hashmap_callbacks {
    void        (*free_obj)(void *obj);          /* Callback to free a value */
    void        (*free_key_data)(void *obj);     /* Callback to free a key */
    void        *(*copy_key_data)(void *src);    /* Callback to copy a key (deep copy) */
    u64         (*hash)(void *);                 /* Callback to hash a key */
    s8          (*key_cmp)(void *a, void *b);   /* Callback to compare two keys */
} HashMap_callbacks;


/**
 * @struct HashMap
 * @brief Main hash map structure.
 *
 * - entries:         Array of pointers to linked lists of entries (buckets).
 * - cb:              Callbacks for key/value operations.
 * - capacity:        Number of buckets (always a prime number).
 * - size:            Number of key-value pairs currently stored.
 * - mtx:             Mutex for thread safety.
 * - size:            Current number of entries in the hash map.
 */
typedef struct s_hashmap {
    t_list              **entries;
    HashMap_callbacks   cb;
    size_t              capacity;
    Mtx                 mtx;
    size_t				size;			
} HashMap;

/**
 * @struct HashMap_it
 * @brief Iterator for traversing all entries in a hash map.
 *
 * Use with hashmap_iterator() and hashmap_next().
 */
typedef struct s_hashmap_it {
    u64			key;			/* Hash value of the current key */
    void 		*value;			/* Value of the current entry */
    HashMap		*_map;			/* Internal: pointer to the hash map */
    size_t		_idx;			/* Internal: current bucket index */
    t_list		*_current;		/* Internal: current node in the bucket */
} HashMap_it;

/* ======================= CONSTANTS & MACROS ======================= */

/* Recommended initial capacities (prime numbers) */
#define HASHMAP_SIZE_100		151U
#define HASHMAP_SIZE_1000		1009U
#define HASHMAP_SIZE_2000		2053U
#define HASHMAP_SIZE_4000		4099U

/* Return values for hashmap_set_entry and others */
#define HASHMAP_UPT_ENTRY		0	/* Updated existing entry */
#define HASHMAP_ADD_ENTRY		1	/* Added new entry */
#define HASHMAP_MALLOC_ERROR	2	/* Memory allocation error */
#define HASHMAP_DATA_REMOVED	3	/* Entry removed and value freed */
#define HASHMAP_ENTRY_FREE		4	/* Entry removed, value NOT freed */
#define HASHMAP_NOT_FOUND		5	/* Entry not found */

/* Remove entry: free value or not */
#define HASHMAP_KEEP_DATA		0	/* Only free entry and key, not value */
#define HASHMAP_FREE_DATA		1	/* Free value using free_obj */

/* Entry validity check */
#define HASHMAP_VALID_ENTRY(entry)	((entry)->value != NULL)

/* Entry key comparison macro (uses user-provided key_cmp) */
#define HASHMAP_SAME_ENTRY(_map_, _entry_, _key_cmp_, _ptr_) (\
    (_entry_)->key == (_key_cmp_) &&\
    (_map_)->cb.key_cmp((_entry_)->key_data, (_ptr_)) \
)

/* Compute bucket index from hash and capacity */
#define HASHMAP_INDEX(key, capacity) ((size_t)((key) % (size_t)(capacity)))

/* ======================= FUNCTION PROTOTYPES ======================= */

/**
 * @brief Initialize a new hash map.
 * @param capacity Initial capacity (will be rounded up to next prime)
 * @param cb Callbacks for key/value operations (must be provided)
 * @return Pointer to new HashMap, or NULL on failure
 *
 * All function pointers must be provided and must be compatible with the key/value types.
 
 * @example
 * HashMap_callbacks cb = {
 *   .free_obj = free_value_function,
 *   .free_key_data = free_key_function,
 *   .copy_key_data = copy_key_function,
 *   .hash = hash_function,
 *   .key_cmp = compare_function
 *  };
 * HashMap *map = hashmap_init(100, cb);
 */
HashMap *hashmap_init (size_t capacity, HashMap_callbacks cb);

/**
 * @brief Destroy a hash map and free all memory (keys, values, entries).
 * @param map HashMap to destroy
 */
void hashmap_destroy(HashMap *map);

/**
 * @brief Retrieve the value associated with a key.
 * @param map HashMap to search
 * @param ptr Pointer to key data
 * @return Pointer to value, or NULL if not found
 */
void *hashmap_get(HashMap *map, void *ptr);

/**
 * @brief Insert or update a key-value pair in the hash map.
 * @param map HashMap to modify
 * @param ptr Pointer to key data, not heap-allocated (will be copied by copy_key_data).
 * @param value Pointer to value data, MUST be heap-allocated.
 * @return HASHMAP_ADD_ENTRY if added, HASHMAP_UPT_ENTRY if updated, HASHMAP_MALLOC_ERROR on error
 *
 * The map takes ownership of the key and value (they will be freed by the map).
 */
s8 hashmap_set_entry(HashMap *map, void *ptr, void *value);

/**
 * @brief Remove an entry by key.
 * @param map HashMap to modify
 * @param ptr Pointer to key data
 * @param free_data HASHMAP_KEEP_DATA to keep value, HASHMAP_FREE_DATA to free value
 * @return HASHMAP_DATA_REMOVED if removed and value freed, HASHMAP_ENTRY_FREE if removed but value kept, HASHMAP_NOT_FOUND if not found
 */
s8 hashmap_remove_entry(HashMap *map, void *ptr, s8 free_data);

/**
 * @brief Get the number of entries in the hash map.
 * @param map HashMap to query
 * @return Number of entries
 */
size_t hashmap_size(HashMap *map);

/**
 * @brief Get the current capacity (number of buckets) of the hash map.
 * @param map HashMap to query
 * @return Capacity (number of buckets)
 */
size_t hashmap_capacity(HashMap *map);

/**
 * @brief Create an iterator for traversing the hash map.
 * @param map HashMap to iterate
 * @return Iterator positioned at the first entry (or end if empty)
 */
HashMap_it hashmap_iterator(HashMap *map);

/**
 * @brief Advance the iterator to the next entry.
 * @param it Iterator to advance
 * @return TRUE if moved to next entry, FALSE if at end
 *
 * After each call, it->key and it->value point to the current entry.
 */
s8 hashmap_next(HashMap_it *it);

/**
 * @brief Expand the hash map's capacity (rehash all entries).
 * @param map HashMap to expand
 * @return TRUE if successful, FALSE on allocation failure
 *
 * Called automatically as needed, but can be called manually.
 */
s8 hashmap_expand(HashMap *map);

#endif /* HEADER_HASHMAP_H */