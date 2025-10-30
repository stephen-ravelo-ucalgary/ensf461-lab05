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
    _arena_start->fwd = NULL;
    _arena_start->bwd = NULL;
    printf("...arena starts at %p\n", _arena_start);
    printf("...arena ends at %p\n", _arena_start+size);

    statusno = 0;

    return size;
}

int mydestroy()
{
    printf("Destroying Arena:\n");
    if (!_arena_start) { return statusno; }
    printf("...unmapping arena with munmap()\n");
    int err = munmap(_arena_start, _arena_start->size);
    _arena_start = NULL;
    statusno = ERR_UNINITIALIZED;
    return err;
}

void* myalloc(size_t size)
{
    if (!_arena_start) { return NULL; } 

    node_t *ptr = _arena_start;
    while (ptr->fwd != NULL) { ptr = ptr->fwd; }
    
    node_t *chunk = mmap(ptr + sizeof(node_t), size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    return chunk;
}

void myfree(void *ptr)
{
    // ((void *)a) - sizeof(node_t)
}