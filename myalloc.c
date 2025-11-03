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
        statusno = 0;
    } else {
        statusno = ERR_CALL_FAILED;
    }
}

#if 0
#define PRINTF_GREEN(...) fprintf(stderr, "\033[32m"); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\033[0m");

void print_header(node_t *header){
  //Note: These printf statements may produce a segmentation fault if the buff
  //pointer is incorrect, e.g., if buff points to the start of the arena.
  printf("Header->size: %lu\n", header->size);
  printf("Header->fwd: %p\n", header->fwd);
  printf("Header->bwd: %p\n", header->bwd);
  printf("Header->is_free: %d\n", header->is_free);
}

// PRINTF_GREEN("Assert %d passed!\n", test++);

void test1() {
  int size = 0, test = 1;
  int page_size = getpagesize();
  void *buff, *buff2 = NULL;
 
  PRINTF_GREEN(">> Testing allocations without the possibility to split. No Frees. (test_allocation_basic)\n");

  buff = myalloc(page_size);
  assert(statusno == ERR_UNINITIALIZED);
  PRINTF_GREEN("Assert %d passed!\n", test++);
  assert(buff == NULL);
  PRINTF_GREEN("Assert %d passed!\n", test++);

  // Allocation not possible because we didn't account for the header which is
  // also placed in the arena and takes of sizeof(node_t) bytes. 
  myinit(page_size);
  buff = myalloc(page_size); 
  assert(statusno == ERR_OUT_OF_MEMORY);
  PRINTF_GREEN("Assert %d passed!\n", test++);
  assert(buff == NULL);
  PRINTF_GREEN("Assert %d passed!\n", test++);

  size = page_size-sizeof(node_t);
  buff = myalloc(size); 
  assert(buff != NULL);
  PRINTF_GREEN("Assert %d passed!\n", test++);

  // Check that we can write to the allocated memory  
  memset(buff, 'a', size);
  assert(((char *)buff)[0] == 'a' && ((char *)buff)[size-1] == 'a');
  PRINTF_GREEN("Assert %d passed!\n", test++);

  //This allocation should fail because the previous allocation used all of
  //the remaining space. 
  buff2 = myalloc(1); 
  assert(buff2 == NULL);  
  PRINTF_GREEN("Assert %d passed!\n", test++);
  assert(statusno == ERR_OUT_OF_MEMORY);
  PRINTF_GREEN("Assert %d passed!\n", test++);
  
  mydestroy();
}

void test2() {
    myinit(getpagesize());
    void *buff1 = myalloc(1);
    myfree(buff1);
    void *buff2 = myalloc(1);
    mydestroy();
}


void test3() {
    int test=1;
    int size =0;
    int page_size = getpagesize();
    void *buff = NULL, *buff2 = NULL;
    node_t *header = NULL, *header2 = NULL; 

    myinit(page_size);
    buff = myalloc(64);
    //This should leave 10 bytes remaining in the arena
    size = page_size - 64 - (sizeof(node_t) * 2) - 10;
    buff2 = myalloc(size);

    header2 = (node_t *)(buff2 - sizeof(node_t));
    print_header(header2);

    printf("DEBUG: header size = %ld\n", header2->size);

    assert(header2->size == size + 10);
    PRINTF_GREEN("Assert %d passed!\n", test++);
    assert(header2->fwd == NULL);
    PRINTF_GREEN("Assert %d passed!\n", test++);

    mydestroy();
}

int main() {
    test();
}
#endif
