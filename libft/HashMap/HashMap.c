/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   HashMap.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: nfour <nfour@student.42angouleme.fr>       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/04/29 19:35:27 by nfour             #+#    #+#             */
/*   Updated: 2025/06/26 09:37:53 by nfour            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "HashMap.h"
#include "primeNumber.h"

// For refactor this to be able to use all type of input value we want we need to:
// 1. Use a void pointer for the value in the HashMap_entry structure. ( Replace BlockPos by void* )
// 2. The user will have to provide a hash function to hash the input value to a key.
// 3. The user will have to provide a comparison function to compare the input value with the key.
// 4. The user will have to provide a copy function to copy the input value

// HashMap *hashmap_init(size_t capacity, void (*free_obj)(void *obj)) {
HashMap *hashmap_init (size_t capacity, HashMap_callbacks cb)
{
	HashMap *map = NULL;
	size_t	prime_capacity = GET_NEXT_PRIME(capacity);

	if (!cb.hash || !cb.copy_key_data || !cb.free_obj || !cb.free_key_data || !cb.key_cmp) {
		return (NULL);
	} else if (!(map = ft_calloc(sizeof(HashMap), 1))) {
		return (NULL);
	} else if (!(map->entries = ft_calloc(sizeof(HashMap_entry), prime_capacity))) {
		free(map);
		return (NULL);
	}

	mtx_init(&map->mtx);
	map->capacity = prime_capacity;
	map->size = 0;
	map->cb.free_obj = cb.free_obj;
    map->cb.free_key_data = cb.free_key_data;
    map->cb.copy_key_data = cb.copy_key_data;
    map->cb.hash = cb.hash;
    map->cb.key_cmp = cb.key_cmp;
    
	return (map);
}

void free_entry(HashMap *map, void *entry) {
    map->cb.free_key_data(((HashMap_entry *)entry)->key_data);
    map->cb.free_obj(((HashMap_entry *)entry)->value);
    free(entry); /* free the entry t_list node */
}



void lst_clear_entry(HashMap *map, t_list **lst) {
    t_list *current = *lst;
    t_list *next;

    while (current) {
        next = current->next;
        free_entry(map, current->content);
        free(current); /* free the t_list node */
        current = next;
    }
    *lst = NULL; /* Set the list to NULL after clearing */
}

void hashmap_destroy(HashMap *map) {
	if (!map) {
		return ;
	}
    for (size_t i = 0; i < map->capacity; i++) {
        lst_clear_entry(map, &map->entries[i]);
    }
	mtx_destroy(&map->mtx);
	free(map->entries); /* free entry t_list ** array */
	free(map);			/* free map */
}

void *hashmap_get(HashMap *map, void *ptr) {
	u64		key = map->cb.hash(ptr);
	t_list	*entry =  NULL;
	void	*ret = NULL;
	size_t	index;

	if (!map) {
		return (NULL);
	}
	mtx_lock(&map->mtx);
	index = HASHMAP_INDEX(key, map->capacity);
	entry = map->entries[index];
	while (entry) {
		HashMap_entry *e = (HashMap_entry *)entry->content;
		if (HASHMAP_SAME_ENTRY(map, e, key, ptr)) {
			ret = e->value;
			break ;
		}
		entry = entry->next;
	}
	mtx_unlock(&map->mtx);
	return (ret);
}

FT_INLINE void hashmap_entry_update(HashMap *map, HashMap_entry *dst, void *ptr, u64 key, void *value) {
    dst->key_data = map->cb.copy_key_data(ptr);
    dst->key = key;
	dst->value = value;
    // printf("hashmap_entry_update: key_data %d, key %llu, value %s\n", *(int *)dst->key_data, dst->key, (char *)dst->value);
}

s8 hashmap_search_entry_update(HashMap *map, size_t index, u64 key, void *ptr, void *value) {
	t_list			*current = NULL;
	HashMap_entry	*new_entry = NULL;
	HashMap_entry	*entry = NULL;

	current = map->entries[index];
	while (current) {
		entry = current->content;
		if (HASHMAP_SAME_ENTRY(map, entry, key, ptr)) {
			free_entry(map, entry);
			if (!(new_entry = malloc(sizeof(HashMap_entry)))) {
				return (HASHMAP_MALLOC_ERROR);
			}
			hashmap_entry_update(map, new_entry, ptr, key, value);
			current->content = new_entry;
			return (HASHMAP_UPT_ENTRY);
		}
		current = current->next;
	}
	return (HASHMAP_NOT_FOUND);
}

s8 hashmap_set_entry(HashMap *map, void *ptr, void *value) {
	t_list	*entry_node = NULL;
	u64		key = map->cb.hash(ptr);
	size_t	index = HASHMAP_INDEX(key, map->capacity);
	s8		ret = HASHMAP_NOT_FOUND;

	mtx_lock(&map->mtx);
	if (( ret = hashmap_search_entry_update(map, index, key, ptr, value)) != HASHMAP_NOT_FOUND) {
		mtx_unlock(&map->mtx);
		return (ret);
	} else if (!(entry_node = ft_lstnew(malloc(sizeof(HashMap_entry))))) {
		mtx_unlock(&map->mtx);
		return (HASHMAP_MALLOC_ERROR);
	}
	hashmap_entry_update(map, (HashMap_entry *)entry_node->content, ptr, key, value);
	ft_lstadd_front(&map->entries[index], entry_node);
	(map->size)++;
	mtx_unlock(&map->mtx);
	return (HASHMAP_ADD_ENTRY);
}

s8 hashmap_remove_entry(HashMap *map, void *ptr, s8 free_data) {
    u64		key = map->cb.hash(ptr);
    size_t	index = HASHMAP_INDEX(key, map->capacity);
    t_list	*current = NULL, *prev = NULL;
	s8		ret = HASHMAP_NOT_FOUND;

	mtx_lock(&map->mtx);
	current = map->entries[index];
    /* loop on linked list of the computed index */
    while (current) {
        HashMap_entry *entry = (HashMap_entry *)current->content;
        if (HASHMAP_SAME_ENTRY(map, entry, key, ptr)) {
			/* If is the first node of list update directly map entry, otherwise update prev->next */
			prev == NULL ? (map->entries[index] = current->next) : (prev->next = current->next); 
			/* If free data, free it otherwise just free entry struct and key_data (keep value pointer alive)*/
			if (free_data == HASHMAP_FREE_DATA) {
                free_entry(map, entry);
                ret = HASHMAP_DATA_REMOVED;
            } else {
                map->cb.free_key_data(entry->key_data);
                free(entry);
                ret = HASHMAP_ENTRY_FREE;
            } 
			/* free node and set it to NULL */
			free(current);
			current = NULL;
            (map->size)--;
			mtx_unlock(&map->mtx);
            return (ret);
        }
        prev = current;
        current = current->next;
    }
	mtx_unlock(&map->mtx);
	return (ret);
}



s8 hashmap_expand(HashMap *map) 
{
    size_t	new_capacity = 0;
    t_list	**new_entries = NULL;
	
	mtx_lock(&map->mtx);
	new_capacity = (map->capacity * 2);
	new_capacity = GET_NEXT_PRIME(new_capacity);
	/* Allocate new entries array */
    if (!(new_entries = ft_calloc(sizeof(t_list *), new_capacity))) {
        return (FALSE);
    }

    /* Rehash and move existing entries to the new array */
    for (size_t i = 0; i < map->capacity; i++) {
        t_list *current = map->entries[i];
        while (current) {
            HashMap_entry *entry = (HashMap_entry *)current->content;
            size_t new_index = HASHMAP_INDEX(entry->key, new_capacity); /* Calculate new index */
            ft_lstadd_front(&new_entries[new_index], ft_lstnew(entry));
            current = current->next;
        }
    }

    for (size_t i = 0; i < map->capacity; i++) {
		ft_lstclear_nodeptr(map->entries + i);
	}
    /* Free old entries */
    free(map->entries);
    
    /* Update hashmap with new capacity and entries */
    map->entries = new_entries;
    map->capacity = new_capacity;

	mtx_unlock(&map->mtx);
    return (TRUE); /* Expansion successful */
}

size_t hashmap_size(HashMap *map) {
	size_t size;

	mtx_lock(&map->mtx);
    size = map->size;
	mtx_unlock(&map->mtx);
	return (size);
}

size_t hashmap_capacity(HashMap *map) {
	size_t capacity;

	mtx_lock(&map->mtx);
	capacity = map->capacity;
	mtx_unlock(&map->mtx);
	return (capacity);
}

HashMap_it hashmap_iterator(HashMap *map) {
    HashMap_it it;

	mtx_lock(&map->mtx);
    it._map = map;
    it._idx = 0;
	it._current = NULL;
	mtx_unlock(&map->mtx);
    return (it);
}

s8 hashmap_next(HashMap_it *it) {
    HashMap	*map = it->_map;
	t_list	*entry_node = NULL;

	mtx_lock(&map->mtx);

    /* Loop through the entries array */
    while (it->_idx < map->capacity) {
        entry_node = map->entries[it->_idx];
        if (entry_node != NULL) { /* Found a non-empty list */
			/* If it's the first node in the list, set it as the current node, Otherwise, move to the next node in the list */
			it->_current = it->_current == NULL ? entry_node : it->_current->next;
            if (it->_current != NULL) {
                /* Go to the next entry list */
                HashMap_entry *entry_tmp = it->_current->content;
                it->key = entry_tmp->key;
                it->value = entry_tmp->value;
				mtx_unlock(&map->mtx);
                return (TRUE);
            }
        }
        (it->_idx)++;
        it->_current = NULL; /* Reset the list node pointer for the next iteration */
    }
    /* No more non-empty entries found */
	mtx_unlock(&map->mtx);
    return (FALSE);
}