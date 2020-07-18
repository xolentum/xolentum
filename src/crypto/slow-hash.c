// Copyright (c) 2018-2020, The NERVA Project
#include "hash-ops.h"

void cn_slow_hash(const void *data, size_t length, char *hash)
{ 
    static void (*const extra_hashes[4])(const void *, size_t, char *) = {
        hash_extra_blake, hash_extra_groestl, hash_extra_jh, hash_extra_skein
    };

    cn_fast_hash(data, length, hash);
    for (uint16_t i = 0; i < 2048; i++)
        extra_hashes[hash[0] & 3](hash, 32, hash); 
}
