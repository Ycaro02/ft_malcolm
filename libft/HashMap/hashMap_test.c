#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "HashMap.h"
#include "primeNumber.h"
#include "../libft.h"

// void dumbTestHashFunct() {


// 	for (s32 x = 0; x < 2; x++) {
// 		for (s32 y = 0; y < 2; y++) {
// 			for (s32 z = 0; z < 2; z++) {
// 				printf(ORANGE"BlockPos |%d|%d||%d|"RESET" "ORANGE"hash: %lu"RESET" "RED"idx: %lu\n"RESET, x, y, z, hash_block_position(x, y, z), HASHMAP_INDEX(hash_block_position(x, y, z), HASHMAP_SIZE_4000));
// 			}
// 		}
// 	}

// }



// --- Fonctions utilitaires pour int ---
s8 int_cmp(void *a, void *b) {
    return (*(int *)a == *(int *)b);
}

u64 u64_hash(void *a) {
    int x = *(int *)a;
    u64 hash = (u64)x;
    hash = ((hash >> 16) ^ hash) * 0x45d9f3b;
    hash = ((hash >> 16) ^ hash) * 0x45d9f3b;
    hash = (hash >> 16) ^ hash;
    return hash;
}

void *int_cpy(void *src) {
    int *dst = malloc(sizeof(int));
    if (!dst) {
        return NULL;
    }
    *(int *)dst = *(int *)src;
    return dst;
}

void int_free(void *a) {
    free(a);
}
// --- End int ---

HashMap *int_init_hashmap(int capacity) {
	HashMap_callbacks cb = {
		.free_obj = int_free,
		.free_key_data = int_free,
		.copy_key_data = int_cpy,
		.hash = u64_hash,
		.key_cmp = int_cmp
	};
	return hashmap_init(capacity, cb);
}


#include <string.h>
void hashmap_test_basic_int() {
    HashMap *map = int_init_hashmap(8);
    assert(map != NULL);

    int k1 = 1, k2 = 2, k3 = 3;
    assert(hashmap_set_entry(map, &k1, strdup("Value1")) == HASHMAP_ADD_ENTRY);
    assert(hashmap_set_entry(map, &k2, strdup("Value2")) == HASHMAP_ADD_ENTRY);
    assert(hashmap_set_entry(map, &k3, strdup("Value3")) == HASHMAP_ADD_ENTRY);

    int q1 = 1, q2 = 2, q3 = 3, q4 = 4;
    assert(!strcmp(hashmap_get(map, &q1), "Value1"));
    assert(!strcmp(hashmap_get(map, &q2), "Value2"));
    assert(!strcmp(hashmap_get(map, &q3), "Value3"));
    assert(hashmap_get(map, &q4) == NULL);

    // Update
    assert(hashmap_set_entry(map, &k1, strdup("UpdatedValue")) == HASHMAP_UPT_ENTRY);
    assert(!strcmp(hashmap_get(map, &q1), "UpdatedValue"));

    // Remove
    assert(hashmap_set_entry(map, &k2, NULL) == HASHMAP_UPT_ENTRY);
    assert(hashmap_get(map, &q2) == NULL);

    hashmap_destroy(map);
    printf("hashmap_test_basic_int passed!\n");
}

void hashmap_test_collision_int() {
    HashMap *map = int_init_hashmap(4);
    assert(map != NULL);

    int keys[] = {1, 5, 9, 13, 17, 21, 25};
    const char *vals[] = {"V1", "V2", "V3", "V4", "V5", "V6", "V7"};
    for (int i = 0; i < 7; ++i)
        assert(hashmap_set_entry(map, &keys[i], strdup(vals[i])) == HASHMAP_ADD_ENTRY);

    for (int i = 0; i < 7; ++i)
        assert(!strcmp(hashmap_get(map, &keys[i]), vals[i]));

    hashmap_destroy(map);
    printf("hashmap_test_collision_int passed!\n");
}

void hashmap_test_expand_int() {
    HashMap *map = int_init_hashmap(3);
    assert(map != NULL);

    int k1 = 1, k2 = 5, k3 = 9;
    assert(hashmap_set_entry(map, &k1, strdup("V1")) == HASHMAP_ADD_ENTRY);
    assert(hashmap_set_entry(map, &k2, strdup("V2")) == HASHMAP_ADD_ENTRY);
    assert(hashmap_set_entry(map, &k3, strdup("V3")) == HASHMAP_ADD_ENTRY);

    assert(map->capacity == 3);
    assert(hashmap_expand(map));
    assert(map->capacity > 3);

    int k4 = 13, k5 = 17;
    assert(hashmap_set_entry(map, &k4, strdup("V4")) == HASHMAP_ADD_ENTRY);
    assert(hashmap_set_entry(map, &k5, strdup("V5")) == HASHMAP_ADD_ENTRY);

    assert(!strcmp(hashmap_get(map, &k1), "V1"));
    assert(!strcmp(hashmap_get(map, &k2), "V2"));
    assert(!strcmp(hashmap_get(map, &k3), "V3"));
    assert(!strcmp(hashmap_get(map, &k4), "V4"));
    assert(!strcmp(hashmap_get(map, &k5), "V5"));

    hashmap_destroy(map);
    printf("hashmap_test_expand_int passed!\n");
}

void hashmap_test_size_int() {
    HashMap *map = int_init_hashmap(11);
    assert(map != NULL);

    assert(hashmap_size(map) == 0);

    int k1 = 1, k2 = 2, k3 = 3;
    hashmap_set_entry(map, &k1, strdup("V1"));
    assert(hashmap_size(map) == 1);
    hashmap_set_entry(map, &k2, strdup("V2"));
    hashmap_set_entry(map, &k3, strdup("V3"));
    assert(hashmap_size(map) == 3);

    hashmap_destroy(map);
    printf("hashmap_test_size_int passed!\n");
}


void hashmap_remove_entry_test_int() {
    HashMap *map = int_init_hashmap(8);
    assert(map != NULL);

    int k1 = 1, k2 = 2, k3 = 3;
    hashmap_set_entry(map, &k1, strdup("A"));
    hashmap_set_entry(map, &k2, strdup("B"));

    // Remove existing key (with free)
    assert(hashmap_remove_entry(map, &k2, HASHMAP_FREE_DATA) == HASHMAP_DATA_REMOVED);
    assert(hashmap_get(map, &k2) == NULL);
    assert(hashmap_size(map) == 1);

    // Remove non-existing key
    assert(hashmap_remove_entry(map, &k3, HASHMAP_FREE_DATA) == HASHMAP_NOT_FOUND);

    // Remove last key
    assert(hashmap_remove_entry(map, &k1, HASHMAP_FREE_DATA) == HASHMAP_DATA_REMOVED);

    assert(hashmap_size(map) == 0);

    hashmap_destroy(map);
    printf("hashmap_remove_entry_test_int passed!\n");
}

void hashmap_iterator_test_int() {
    HashMap *map = int_init_hashmap(8);
    assert(map != NULL);

    int keys[] = {1, 2, 3, 4, 5};
    const char *vals[] = {"A", "B", "C", "D", "E"};
    for (int i = 0; i < 5; ++i)
        hashmap_set_entry(map, &keys[i], strdup(vals[i]));

    int found[5] = {0};
    HashMap_it it = hashmap_iterator(map);
    while (hashmap_next(&it)) {
        int *k = (int*)(((HashMap_entry*)it._current->content)->key_data);
        char *v = (char*)it.value;
        for (int i = 0; i < 5; ++i) {
            if (*k == keys[i]) {
                assert(strcmp(v, vals[i]) == 0);
                found[i] = 1;
            }
        }
    }
    for (int i = 0; i < 5; ++i)
        assert(found[i] == 1);

    hashmap_destroy(map);
    printf("hashmap_iterator_test_int passed!\n");
}

void int_test() {
    hashmap_test_basic_int();
    hashmap_test_collision_int();
    hashmap_test_expand_int();
    hashmap_test_size_int();
    hashmap_remove_entry_test_int();
    hashmap_iterator_test_int();
}



// --- Fonctions utilitaires pour string ---
s8 str_cmp(void *a, void *b) {
    return strcmp((char *)a, (char *)b) == 0;
}

u64 str_hash(void *a) {
    // djb2 hash
    unsigned char *str = (unsigned char *)a;
    u64 hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

void *str_cpy(void *src) {
    return strdup((char *)src);
}

void str_free(void *a) {
    free(a);
}
// --- End string ---

HashMap *str_hashmap_init(int capacity) {
	HashMap_callbacks cb = {
		.free_obj = str_free,
		.free_key_data = str_free,
		.copy_key_data = str_cpy,
		.hash = str_hash,
		.key_cmp = str_cmp
	};
	return hashmap_init(capacity, cb);
}

void hashmap_test_basic_str() {
    HashMap *map = str_hashmap_init(8);
    assert(map != NULL);

    char *k1 = "foo", *k2 = "bar", *k3 = "baz";
    assert(hashmap_set_entry(map, k1, strdup("Value1")) == HASHMAP_ADD_ENTRY);
    assert(hashmap_set_entry(map, k2, strdup("Value2")) == HASHMAP_ADD_ENTRY);
    assert(hashmap_set_entry(map, k3, strdup("Value3")) == HASHMAP_ADD_ENTRY);

    assert(!strcmp(hashmap_get(map, k1), "Value1"));
    assert(!strcmp(hashmap_get(map, k2), "Value2"));
    assert(!strcmp(hashmap_get(map, k3), "Value3"));
    assert(hashmap_get(map, "qux") == NULL);

    // Update
    assert(hashmap_set_entry(map, k1, strdup("UpdatedValue")) == HASHMAP_UPT_ENTRY);
    assert(!strcmp(hashmap_get(map, k1), "UpdatedValue"));

    // Remove
    assert(hashmap_set_entry(map, k2, NULL) == HASHMAP_UPT_ENTRY);
    assert(hashmap_get(map, k2) == NULL);

    hashmap_destroy(map);
    printf("hashmap_test_basic_str passed!\n");
}

void hashmap_test_collision_str() {
    HashMap *map = str_hashmap_init(4);
    assert(map != NULL);

    char *keys[] = {"foo", "oof", "bar", "baz", "rab", "qux", "xuq"};
    const char *vals[] = {"V1", "V2", "V3", "V4", "V5", "V6", "V7"};
    for (int i = 0; i < 7; ++i)
        assert(hashmap_set_entry(map, keys[i], strdup(vals[i])) == HASHMAP_ADD_ENTRY);

    for (int i = 0; i < 7; ++i)
        assert(!strcmp(hashmap_get(map, keys[i]), vals[i]));

    hashmap_destroy(map);
    printf("hashmap_test_collision_str passed!\n");
}

void hashmap_test_expand_str() {
    HashMap *map = str_hashmap_init(3);
    assert(map != NULL);

    char *k1 = "foo", *k2 = "bar", *k3 = "baz";
    assert(hashmap_set_entry(map, k1, strdup("V1")) == HASHMAP_ADD_ENTRY);
    assert(hashmap_set_entry(map, k2, strdup("V2")) == HASHMAP_ADD_ENTRY);
    assert(hashmap_set_entry(map, k3, strdup("V3")) == HASHMAP_ADD_ENTRY);

    assert(map->capacity == 3);
    assert(hashmap_expand(map));
    assert(map->capacity > 3);

    char *k4 = "qux", *k5 = "quux";
    assert(hashmap_set_entry(map, k4, strdup("V4")) == HASHMAP_ADD_ENTRY);
    assert(hashmap_set_entry(map, k5, strdup("V5")) == HASHMAP_ADD_ENTRY);

    assert(!strcmp(hashmap_get(map, k1), "V1"));
    assert(!strcmp(hashmap_get(map, k2), "V2"));
    assert(!strcmp(hashmap_get(map, k3), "V3"));
    assert(!strcmp(hashmap_get(map, k4), "V4"));
    assert(!strcmp(hashmap_get(map, k5), "V5"));

    hashmap_destroy(map);
    printf("hashmap_test_expand_str passed!\n");
}

void hashmap_test_size_str() {
    HashMap *map = str_hashmap_init(11);
    assert(map != NULL);

    assert(hashmap_size(map) == 0);

    char *k1 = "foo", *k2 = "bar", *k3 = "baz";
    hashmap_set_entry(map, k1, strdup("V1"));
    assert(hashmap_size(map) == 1);
    hashmap_set_entry(map, k2, strdup("V2"));
    hashmap_set_entry(map, k3, strdup("V3"));
    assert(hashmap_size(map) == 3);

    hashmap_destroy(map);
    printf("hashmap_test_size_str passed!\n");
}

void hashmap_remove_entry_test_str() {
    HashMap *map = str_hashmap_init(8);
    assert(map != NULL);

    char *k1 = "foo", *k2 = "bar", *k3 = "baz";
    hashmap_set_entry(map, k1, strdup("A"));
    hashmap_set_entry(map, k2, strdup("B"));

    // Remove existing key (with free)
    assert(hashmap_remove_entry(map, k2, HASHMAP_FREE_DATA) == HASHMAP_DATA_REMOVED);
    assert(hashmap_get(map, k2) == NULL);
    assert(hashmap_size(map) == 1);

    // Remove non-existing key
    assert(hashmap_remove_entry(map, k3, HASHMAP_FREE_DATA) == HASHMAP_NOT_FOUND);

    // Remove last key
    assert(hashmap_remove_entry(map, k1, HASHMAP_FREE_DATA) == HASHMAP_DATA_REMOVED);

    assert(hashmap_size(map) == 0);

    hashmap_destroy(map);
    printf("hashmap_remove_entry_test_str passed!\n");
}

void hashmap_iterator_test_str() {
    HashMap *map = str_hashmap_init(8);
    assert(map != NULL);

    char *keys[] = {"foo", "bar", "baz", "qux", "quux"};
    const char *vals[] = {"A", "B", "C", "D", "E"};
    for (int i = 0; i < 5; ++i)
        hashmap_set_entry(map, keys[i], strdup(vals[i]));

    int found[5] = {0};
    HashMap_it it = hashmap_iterator(map);
    while (hashmap_next(&it)) {
        char *k = (char*)(((HashMap_entry*)it._current->content)->key_data);
        char *v = (char*)it.value;
        for (int i = 0; i < 5; ++i) {
            if (strcmp(k, keys[i]) == 0) {
                assert(strcmp(v, vals[i]) == 0);
                found[i] = 1;
            }
        }
    }
    for (int i = 0; i < 5; ++i)
        assert(found[i] == 1);

    hashmap_destroy(map);
    printf("hashmap_iterator_test_str passed!\n");
}

void test_str() {
    hashmap_test_basic_str();
    hashmap_test_collision_str();
    hashmap_test_expand_str();
    hashmap_test_size_str();
    hashmap_remove_entry_test_str();
    hashmap_iterator_test_str();
}


typedef struct PACKED_STRUCT s_block_pos {
    int x;
    int y;
    int z;
} BlockPos;

typedef struct s_complex_value {
    char *name;
    char *desc;
    int   value;
} ComplexValue;

// --- Fonctions utilitaires pour BlockPos ---
s8 blockpos_cmp(void *a, void *b) {
    BlockPos *pa = (BlockPos *)a;
    BlockPos *pb = (BlockPos *)b;
    return pa->x == pb->x && pa->y == pb->y && pa->z == pb->z;
}

u64 hash_block(void *p) {
    BlockPos *pos = (BlockPos *)p;
    int x = pos->x;
    int y = pos->y;
    int z = pos->z;
    const u64 prime1 = 73856093;
    const u64 prime2 = 19349663;
    const u64 prime3 = 83492791;

    u64 hash = x * prime1 ^ y * prime2 ^ z * prime3;
    hash = ((hash >> 16) ^ hash) * 0x45d9f3b;
    hash = ((hash >> 16) ^ hash) * 0x45d9f3b;
    hash = (hash >> 16) ^ hash;
    return hash;
}

void *blockpos_cpy(void *src) {
    BlockPos *dst = malloc(sizeof(BlockPos));
    if (!dst) return NULL;
    *dst = *(BlockPos *)src;
    return dst;
}

void blockpos_free(void *a) {
    free(a);
}
// --- End BlockPos ---

// --- Fonctions utilitaires pour ComplexValue ---
void *complex_cpy(void *src) {
    ComplexValue *orig = (ComplexValue *)src;
    ComplexValue *copy = malloc(sizeof(ComplexValue));
    if (!copy) return NULL;
    copy->name = strdup(orig->name);
    copy->desc = strdup(orig->desc);
    copy->value = orig->value;
    return copy;
}

void complex_free(void *a) {
    ComplexValue *v = (ComplexValue *)a;
    free(v->name);
    free(v->desc);
    free(v);
}

HashMap *blockpos_hashmap_init(int capacity) {
	HashMap_callbacks cb = {
		.free_obj = complex_free,
		.free_key_data = blockpos_free,
		.copy_key_data = blockpos_cpy,
		.hash = hash_block,
		.key_cmp = blockpos_cmp
	};
	return hashmap_init(capacity, cb);
}

// Test: insertion et récupération
void hashmap_blockpos_set_entry_test() {
    HashMap *map = blockpos_hashmap_init(8);
    assert(map != NULL);

    BlockPos k1 = {1, 2, 3};
    ComplexValue *v1 = malloc(sizeof(ComplexValue));
    v1->name = strdup("Alpha");
    v1->desc = strdup("First block");
    v1->value = 42;
    assert(hashmap_set_entry(map, &k1, v1) == HASHMAP_ADD_ENTRY);

    ComplexValue *out = hashmap_get(map, &k1);
    assert(out && strcmp(out->name, "Alpha") == 0 && out->value == 42);

    hashmap_destroy(map);
    printf("hashmap_blockpos_set_entry_test passed!\n");
}

// Test: update
void hashmap_blockpos_update_entry_test() {
    HashMap *map = blockpos_hashmap_init(8);
    assert(map != NULL);

    BlockPos k1 = {1, 2, 3};
    ComplexValue *v1 = malloc(sizeof(ComplexValue));
    v1->name = strdup("Alpha");
    v1->desc = strdup("First block");
    v1->value = 42;
    ComplexValue *v1b = malloc(sizeof(ComplexValue));
    v1b->name = strdup("Alpha2");
    v1b->desc = strdup("First block updated");
    v1b->value = 99;
    assert(hashmap_set_entry(map, &k1, v1) == HASHMAP_ADD_ENTRY);
    assert(hashmap_set_entry(map, &k1, v1b) == HASHMAP_UPT_ENTRY);

    ComplexValue *out = hashmap_get(map, &k1);
    assert(out && strcmp(out->name, "Alpha2") == 0 && out->value == 99);

    hashmap_destroy(map);
    printf("hashmap_blockpos_update_entry_test passed!\n");
}

// Test: suppression
void hashmap_blockpos_remove_entry_test() {
    HashMap *map = blockpos_hashmap_init(8);
    assert(map != NULL);

    BlockPos k1 = {1, 2, 3};
    BlockPos k2 = {4, 5, 6};
    ComplexValue *v1 = malloc(sizeof(ComplexValue));
    v1->name = strdup("Alpha");
    v1->desc = strdup("First block");
    v1->value = 42;
    ComplexValue *v2 = malloc(sizeof(ComplexValue));
    v2->name = strdup("Beta");
    v2->desc = strdup("Second block");
    v2->value = 84;
    assert(hashmap_set_entry(map, &k1, v1) == HASHMAP_ADD_ENTRY);
    assert(hashmap_set_entry(map, &k2, v2) == HASHMAP_ADD_ENTRY);

    assert(hashmap_remove_entry(map, &k1, HASHMAP_FREE_DATA) == HASHMAP_DATA_REMOVED);
    assert(hashmap_get(map, &k1) == NULL);
    assert(hashmap_get(map, &k2) != NULL);

    assert(hashmap_remove_entry(map, &k2, HASHMAP_FREE_DATA) == HASHMAP_DATA_REMOVED);
    assert(hashmap_get(map, &k2) == NULL);

    hashmap_destroy(map);
    printf("hashmap_blockpos_remove_entry_test passed!\n");
}

// Test: itérateur
void hashmap_blockpos_iterator_test() {
    HashMap *map = blockpos_hashmap_init(8);
    assert(map != NULL);

    BlockPos k1 = {1, 2, 3}, k2 = {4, 5, 6};
    ComplexValue *v1 = malloc(sizeof(ComplexValue));
    v1->name = strdup("Alpha");
    v1->desc = strdup("First block");
    v1->value = 42;
    ComplexValue *v2 = malloc(sizeof(ComplexValue));
    v2->name = strdup("Beta");
    v2->desc = strdup("Second block");
    v2->value = 84;
    assert(hashmap_set_entry(map, &k1, v1) == HASHMAP_ADD_ENTRY);
    assert(hashmap_set_entry(map, &k2, v2) == HASHMAP_ADD_ENTRY);

    int found_k1 = 0, found_k2 = 0;
    HashMap_it it = hashmap_iterator(map);
    while (hashmap_next(&it)) {
        BlockPos *key = (BlockPos *)(((HashMap_entry*)it._current->content)->key_data);
        ComplexValue *val = (ComplexValue *)it.value;
        if (blockpos_cmp(key, &k1)) {
            assert(strcmp(val->name, "Alpha") == 0);
            found_k1 = 1;
        }
        if (blockpos_cmp(key, &k2)) {
            assert(strcmp(val->desc, "Second block") == 0);
            found_k2 = 1;
        }
    }
    assert(found_k1 && found_k2);

    hashmap_destroy(map);
    printf("hashmap_blockpos_iterator_test passed!\n");
}

// Test de collision (plusieurs clés sur le même index)
void hashmap_blockpos_collision_test() {
    HashMap *map = blockpos_hashmap_init(4);
    assert(map != NULL);

    BlockPos k1 = {1, 2, 3};
    BlockPos k2 = {1, 2, 7}; // Choisis des valeurs qui hashent sur le même index si possible
    ComplexValue *v1 = malloc(sizeof(ComplexValue));
    v1->name = strdup("Alpha");
    v1->desc = strdup("First block");
    v1->value = 42;
    ComplexValue *v2 = malloc(sizeof(ComplexValue));
    v2->name = strdup("Beta");
    v2->desc = strdup("Second block");
    v2->value = 84;

    assert(hashmap_set_entry(map, &k1, v1) == HASHMAP_ADD_ENTRY);
    assert(hashmap_set_entry(map, &k2, v2) == HASHMAP_ADD_ENTRY);

    // Vérifie que les deux sont accessibles
    ComplexValue *out1 = hashmap_get(map, &k1);
    ComplexValue *out2 = hashmap_get(map, &k2);
    assert(out1 && strcmp(out1->name, "Alpha") == 0);
    assert(out2 && strcmp(out2->name, "Beta") == 0);

    // Supprime k1, vérifie que k2 existe toujours
    assert(hashmap_remove_entry(map, &k1, HASHMAP_FREE_DATA) == HASHMAP_DATA_REMOVED);
    assert(hashmap_get(map, &k1) == NULL);
    assert(hashmap_get(map, &k2) != NULL);

    hashmap_destroy(map);
    printf("hashmap_blockpos_collision_test passed!\n");
}

// Test d'expansion automatique
void hashmap_blockpos_expand_test() {
    HashMap *map = blockpos_hashmap_init(2);
    assert(map != NULL);

    // Ajoute assez d'éléments pour forcer l'expansion
    for (int i = 0; i < 20; ++i) {
        BlockPos *k = malloc(sizeof(BlockPos));
        k->x = i; k->y = i * 2; k->z = i * 3;
        ComplexValue *v = malloc(sizeof(ComplexValue));
        char buf[32];
        snprintf(buf, sizeof(buf), "Block%d", i);
        v->name = strdup(buf);
        v->desc = strdup("Expanded");
        v->value = i * 10;
        assert(hashmap_set_entry(map, k, v) == HASHMAP_ADD_ENTRY);
        free(k); // la map fait sa propre copie de la clé
    }
    // Vérifie que tous les éléments sont accessibles
    for (int i = 0; i < 20; ++i) {
        BlockPos k = {i, i * 2, i * 3};
        ComplexValue *out = hashmap_get(map, &k);
        assert(out && out->value == i * 10);
    }
    hashmap_destroy(map);
    printf("hashmap_blockpos_expand_test passed!\n");
}

// Suppression d'une clé inexistante
void hashmap_blockpos_remove_nonexistent_test() {
    HashMap *map = blockpos_hashmap_init(8);
    assert(map != NULL);

    BlockPos k1 = {1, 2, 3};
    ComplexValue *v1 = malloc(sizeof(ComplexValue));
    v1->name = strdup("Alpha");
    v1->desc = strdup("First block");
    v1->value = 42;
    assert(hashmap_set_entry(map, &k1, v1) == HASHMAP_ADD_ENTRY);

    BlockPos k2 = {9, 9, 9};
    assert(hashmap_remove_entry(map, &k2, HASHMAP_FREE_DATA) == HASHMAP_NOT_FOUND);

    hashmap_destroy(map);
    printf("hashmap_blockpos_remove_nonexistent_test passed!\n");
}

// Suppression sans libération de la value (HASHMAP_KEEP_DATA)
void hashmap_blockpos_remove_keep_data_test() {
    HashMap *map = blockpos_hashmap_init(8);
    assert(map != NULL);

    BlockPos k1 = {1, 2, 3};
    ComplexValue *v1 = malloc(sizeof(ComplexValue));
    v1->name = strdup("Alpha");
    v1->desc = strdup("First block");
    v1->value = 42;
    assert(hashmap_set_entry(map, &k1, v1) == HASHMAP_ADD_ENTRY);

    assert(hashmap_remove_entry(map, &k1, HASHMAP_KEEP_DATA) == HASHMAP_ENTRY_FREE);
    // La value n'est pas free, on doit la libérer ici
    complex_free(v1);

    hashmap_destroy(map);
    printf("hashmap_blockpos_remove_keep_data_test passed!\n");
}

// Itérateur sur map vide
void hashmap_blockpos_iterator_empty_test() {
    HashMap *map = blockpos_hashmap_init(8);
    assert(map != NULL);

    HashMap_it it = hashmap_iterator(map);
    assert(hashmap_next(&it) == FALSE);

    hashmap_destroy(map);
    printf("hashmap_blockpos_iterator_empty_test passed!\n");
}

// Itérateur après suppression
void hashmap_blockpos_iterator_after_remove_test() {
    HashMap *map = blockpos_hashmap_init(8);
    assert(map != NULL);

    BlockPos k1 = {1, 2, 3}, k2 = {4, 5, 6}, k3 = {7, 8, 9};
    ComplexValue *v1 = malloc(sizeof(ComplexValue));
    v1->name = strdup("Alpha");
    v1->desc = strdup("First block");
    v1->value = 42;
    ComplexValue *v2 = malloc(sizeof(ComplexValue));
    v2->name = strdup("Beta");
    v2->desc = strdup("Second block");
    v2->value = 84;
    ComplexValue *v3 = malloc(sizeof(ComplexValue));
    v3->name = strdup("Gamma");
    v3->desc = strdup("Third block");
    v3->value = 168;
    assert(hashmap_set_entry(map, &k1, v1) == HASHMAP_ADD_ENTRY);
    assert(hashmap_set_entry(map, &k2, v2) == HASHMAP_ADD_ENTRY);
    assert(hashmap_set_entry(map, &k3, v3) == HASHMAP_ADD_ENTRY);

    // Remove k2
    assert(hashmap_remove_entry(map, &k2, HASHMAP_FREE_DATA) == HASHMAP_DATA_REMOVED);

    int found_k1 = 0, found_k3 = 0;
    HashMap_it it = hashmap_iterator(map);
    while (hashmap_next(&it)) {
        BlockPos *key = (BlockPos *)(((HashMap_entry*)it._current->content)->key_data);
        ComplexValue *val = (ComplexValue *)it.value;
        if (blockpos_cmp(key, &k1)) found_k1 = 1;
        if (blockpos_cmp(key, &k3)) found_k3 = 1;
    }
    assert(found_k1 && found_k3);

    hashmap_destroy(map);
    printf("hashmap_blockpos_iterator_after_remove_test passed!\n");
}

// Test de la taille et de la capacité
void hashmap_blockpos_size_capacity_test() {
    HashMap *map = blockpos_hashmap_init(5);
    assert(map != NULL);

    assert(hashmap_size(map) == 0);
    assert(hashmap_capacity(map) >= 5);

    BlockPos k1 = {1, 2, 3};
    ComplexValue *v1 = malloc(sizeof(ComplexValue));
    v1->name = strdup("Alpha");
    v1->desc = strdup("First block");
    v1->value = 42;
    hashmap_set_entry(map, &k1, v1);
    assert(hashmap_size(map) == 1);

    hashmap_destroy(map);
    printf("hashmap_blockpos_size_capacity_test passed!\n");
}

void test_blockpos_complex() {
    hashmap_blockpos_set_entry_test();
    hashmap_blockpos_update_entry_test();
    hashmap_blockpos_remove_entry_test();
    hashmap_blockpos_iterator_test();
    hashmap_blockpos_collision_test();
    hashmap_blockpos_expand_test();
    hashmap_blockpos_remove_nonexistent_test();
    hashmap_blockpos_remove_keep_data_test();
    hashmap_blockpos_iterator_empty_test();
    hashmap_blockpos_iterator_after_remove_test();
    hashmap_blockpos_size_capacity_test();
}

int main() {
    int_test();
    test_str();
    test_blockpos_complex();
    return 0;
}