#include <stddef.h>
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include "myalloc.h"

node_t *_arena_start;
long _arena_size;
int statusno = ERR_UNINITIALIZED;

int myinit(size_t size)
{
    printf("Initializing arena:\n");
    printf("...requested size %lu bytes\n", size);
    
    if (size > (size_t)MAX_ARENA_SIZE)
    {
        printf("...error: requested size larger than MAX_ARENA_SIZE (%d)\n", MAX_ARENA_SIZE);
        return ERR_BAD_ARGUMENTS;
    }
    
    int pagesize = getpagesize();
    printf("...pagesize is size %d bytes\n", pagesize);
    
    printf("...adjusting size with page boundaries\n");
    if (size % pagesize != 0)
    {
        size = (size / pagesize + 1) * pagesize;
    }
    printf("...adjusted size is %lu bytes\n", size);

    printf("...mapping arena with mmap\n");
    _arena_start = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    _arena_start->size = size - sizeof(node_t);
    _arena_start->is_free = 1;
    _arena_start->fwd = NULL;
    _arena_start->bwd = NULL;
    printf("...arena starts at %p\n", _arena_start);
    printf("...arena ends at %p\n", _arena_start+size);

    _arena_size = _arena_start->size;
    statusno = 0;

    return size;
}

int mydestroy()
{
    printf("Destroying Arena:\n");
    if (!_arena_start) {
        statusno = ERR_UNINITIALIZED;
        return statusno;
    } else if (munmap(_arena_start, _arena_size + sizeof(node_t)) == 0) {
        printf("...unmapping arena with munmap()\n");
        _arena_start = NULL;
        statusno = 0;
        return statusno;
    } else {
        statusno = ERR_CALL_FAILED;
        return statusno;
    }
}

void* myalloc(size_t size)
{
    printf("Allocating memory:\n");
    if (!_arena_start)
    {
        statusno = ERR_UNINITIALIZED;
        return NULL;
    }
    
    printf("...looking for free chunk of >= %ld bytes\n", size);
    node_t *free_chunk = _arena_start;
    while (free_chunk != NULL && (free_chunk->is_free == 0 || free_chunk->size < size))
    {
        free_chunk = free_chunk->fwd;
    }
    
    if (free_chunk == NULL)
    {
        statusno = ERR_OUT_OF_MEMORY;
        return NULL;
    }

    printf("...found free chunk of %ld bytes with header at %p\n", size, free_chunk);
    printf("...free chunk->fwd currently points to %p\n", free_chunk->fwd);
    printf("...free chunk->bwd currently points to %p\n", free_chunk->bwd);
    
    printf("...checking if splitting is required\n");
    if (free_chunk->size > size + sizeof(node_t))
    {
        printf("...splitting required\n");
        node_t *chunk = ((void *) free_chunk) + size + sizeof(node_t);
        chunk->size = free_chunk->size - size - sizeof(node_t);
        chunk->is_free = 1;
        chunk->fwd = NULL;
        chunk->bwd = free_chunk;
        free_chunk->fwd = chunk;
    } else {
        printf("...splitting not required\n");
    }

    printf("...updating chunk header at %p\n", free_chunk);
    free_chunk->is_free = 0;
    if (free_chunk->size - size >= 32)
        free_chunk->size = size;
    
    printf("...allocation starts at %p\n", free_chunk + sizeof(node_t));
    return ((void *)free_chunk) + sizeof(node_t);
}

void myfree(void *ptr)
{
    node_t *chunkHeader = ((void *) ptr) - sizeof(node_t);

    if (chunkHeader->is_free == 1) {
        statusno = ERR_UNINITIALIZED;
    }
    else if (chunkHeader->is_free == 0) {
        chunkHeader->is_free = 1;

        node_t *fwdFreeChunk = chunkHeader->fwd;
        if (fwdFreeChunk) {
            if (fwdFreeChunk->is_free) {
                chunkHeader->size += fwdFreeChunk->size + sizeof(node_t);
                if (fwdFreeChunk->fwd) {
                    fwdFreeChunk->fwd->bwd = chunkHeader;
                }
                chunkHeader->fwd = fwdFreeChunk->fwd;
            }
        }

        node_t *bwdFreeChunk = chunkHeader->bwd;
        if (bwdFreeChunk) {
            if (bwdFreeChunk->is_free) {
                bwdFreeChunk->size += chunkHeader->size + sizeof(node_t);
                if (chunkHeader->fwd) {
                    chunkHeader->fwd->bwd = bwdFreeChunk;
                }
                bwdFreeChunk->fwd = chunkHeader->fwd;
            }
        }
        
        statusno = 0;
    } else {
        statusno = ERR_CALL_FAILED;
    }
}
