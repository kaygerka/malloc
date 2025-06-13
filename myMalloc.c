#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include "myMalloc.h"
#define MALLOC_COLOR "MALLOC_DEBUG_COLOR"

static bool check_env;
static bool use_color;
static void remove_from_freelist(header *block);
static int get_index_for_size(size_t size);
static void insert_into_freelist(header *freelist, header *block);

phread_mutex_t mutex;
//Array of sentinel nodes for the freelists
header freelistSentinels[N_LISTS];
/*
 * Pointer to the second fencepost in the most recently allocated chunk from
 * the OS. Used for coalescing chunks
 */
header * lastFencePost;
void * base;
header * osChunkList [MAX_OS_CHUNKS];
size_t numOsChunks = 0;
/*
 * direct the compiler to run the init function before running main
 * this allows initialization of required globals
 */
static void init (void) __attribute__ ((constructor));

//  HELPER:  for manipulating pointers to headers
static inline header * get_header_from_offset(void * ptr, ptrdiff_t off);
static inline header * get_left_header(header * h);
static inline header * ptr_to_header(void * p);

//  HELPER:  for allocating more memory from the OS
static inline void initialize_fencepost(header * fp, size_t left_size);
static inline void insert_os_chunk(header * hdr);
static inline void insert_fenceposts(void * raw_mem, size_t size);
static header * allocate_chunk(size_t size);

//  HELPER:  for freeing a block
static inline void deallocate_object(void * p);

//  HELPER:  for allocating a block
static inline header * allocate_object(size_t raw_size);

//  HELPER:  for verifying that the data structures are structurally 
// valid
static inline header * detect_cycles();
static inline header * verify_pointers();
static inline bool verify_freelist();
static inline header * verify_chunk(header * chunk);
static inline bool verify_tags();

static void init();
static bool isMallocInitialized;

// HELPER: to retrieve a header pointer from a pointer and an offset
static inline header * get_header_from_offset(void * ptr, ptrdiff_t off) {
	return (header *)((char *) ptr + off);
}


//HELPER: to get the header to the right of a given header
header * get_right_header(header * h) {
	return get_header_from_offset(h, get_size(h));
}


//HELPER: to get the header to the left of a given header
inline static header * get_left_header(header * h) {
  return get_header_from_offset(h, -h->left_size);
}

 //HELPER: Fenceposts are marked as always allocated and may need to have  a left object size to ensure coalescing happens properly
inline static void initialize_fencepost(header * fp, size_t left_size) {
	set_state(fp,FENCEPOST);
	set_size(fp, ALLOC_HEADER_SIZE);
	fp->left_size = left_size;
}

//HELPER:to maintain list of chunks from the OS for debugging
inline static void insert_os_chunk(header * hdr) {
  if (numOsChunks < MAX_OS_CHUNKS) {
    osChunkList[numOsChunks++] = hdr;
  }
}

 /**  HELPER: given a chunk of memory insert fenceposts at the left and 
 * right boundaries of the block to prevent coalescing outside of the
 * block
 */
inline static void insert_fenceposts(void * raw_mem, size_t size) {
  // Convert to char * before performing operations
  char * mem = (char *) raw_mem;

  // Insert a fencepost at the left edge of the block
  header * leftFencePost = (header *) mem;
  initialize_fencepost(leftFencePost, ALLOC_HEADER_SIZE);

  // Insert a fencepost at the right edge of the block
  header * rightFencePost = get_header_from_offset(mem, size - ALLOC_HEADER_SIZE);
  initialize_fencepost(rightFencePost, size - 2 * ALLOC_HEADER_SIZE);
}

 // Allocate another chunk from the OS and prepare to insert it into the free list
static header * allocate_chunk(size_t size) {
  void * mem = sbrk(size);
  insert_fenceposts(mem, size);
  header * hdr = (header *) ((char *)mem + ALLOC_HEADER_SIZE);
  set_state(hdr, UNALLOCATED);
  set_size(hdr, size - 2 * ALLOC_HEADER_SIZE);
  hdr->left_size = ALLOC_HEADER_SIZE;
  return hdr;
}


//Helper allocate an object given a raw request size from the user ===========================================
static inline header * allocate_object(size_t raw_size) {
  // TODO implement allocation  TASK 1 ALLOCATION 

  // Handle zero-byte allocation first
  if (raw_size == 0) {
    return NULL;
  }

  // raw size is rounded up to the nearest 8th byte
  ssize_t userSize = (raw_size + 7) & (~7);
  size_t minUserSize = 16;

  // make sure the minimum size of allocation is 16
  if (userSize < minUserSize) {
    userSize = minUserSize;
  }

  // Total size = size of rounded 8 bytes plus header meta data (16 bytes)
  size_t totalSize = userSize + ALLOC_HEADER_SIZE;

  /*
   * LOOPING THRU FREE LIST TO FIND CORRECT HEADER SIZE FOR THE TOTAL SIZE (RAW+HEADER)

   */
  header *freeObject = NULL;
  int ilist;

  // searches the indices of the free list from 0 - N_LISTS - 1
  for (ilist = 0; ilist < N_LISTS; ilist++) {
    header *freelist = &freelistSentinels[ilist];

    // goes thru all the blocks in the free list from the index = ilist
    for (header *current = freelist->next; current != freelist; current = current->next) {

      // if no free list matched the block needed, we go to the last index
      if (ilist == N_LISTS - 1) {

        // finds the cloesest block memory size to totalSize needed
        while (get_size(current) < totalSize) {
          current = current -> next;
        }
      }

      // if there was a header that matched the total size, we set the freeObject block = current header
      if (get_size(current) >= totalSize) {
        freeObject = current;
        break;
      }
    }

    // if we found a freeObject block break
    if (freeObject) break;
  }


// CASE: NO FREE OBJECT FOUND - we need more memory
  while (!freeObject) {

    // REQUEST: 4096 memory and allocate a new chunk with that size, sets fencpost with allocate_chunk
    size_t chunk_size = ARENA_SIZE;
    header *new_chunk = allocate_chunk(chunk_size);

    // if the allocate new chunk fails, return null
    if (!new_chunk) {
      return NULL;
    }

    // GET LEFT FENCEPOST: by moving backwards from new_chunk
    header *leftFP = get_header_from_offset(new_chunk,  -ALLOC_HEADER_SIZE);

    // ADJACENT FENCEPOSTS: checks if the right header of the last fencepost is the left fencepost of the new chunk added
    if (leftFP == get_right_header(lastFencePost)) {

      // gets the address of the previous block 
      header *lastBlock = get_left_header(lastFencePost);

      // COALESCE: if the previous block before added chunk is UNALLOCATED
      if (!get_state(lastBlock)) {

        // remove the previous block from free list and combine its size with the new chunk and 2 headers
        remove_from_freelist(lastBlock);
        size_t combined_size = get_size(lastBlock) + get_size(new_chunk) + 2 * ALLOC_HEADER_SIZE;

        // set the size of the block as the combined size and as unallocated, and equal that to the new chunk addy
        set_size_and_state(lastBlock, combined_size, UNALLOCATED);
        new_chunk = lastBlock;


      // DO NOT COALESCE: if the previous block is ALLOCATED -- MY BIGGEST PROBLEM LOL - ADJ FENCEPOSTS
      } else {
        
        // set the size and state of the last fencepost = new chunk by adding the new chunk size and 2 headers, and set unallocated
        set_size_and_state(lastFencePost, 2 * ALLOC_HEADER_SIZE + get_size(new_chunk), UNALLOCATED);
        new_chunk = lastFencePost;
      }


    //NO ADJACENT FENCEPOST: insert the left fencepost 
    } else {
        insert_os_chunk(leftFP);
    }

    // UPDATE LAST FENCEPOST: set addy of last fp as right header of new chunk and set left size of new chunk
    lastFencePost = get_right_header(new_chunk);
    lastFencePost -> left_size = get_size(new_chunk);

    // get the index for the chunk size and insert it back into the free list and set freeObject(header for free list)
    int new_list = get_index_for_size(get_size(new_chunk));
    insert_into_freelist(&freelistSentinels[new_list], new_chunk);

    // set freeObject as newly allocated chunk
    freeObject = new_chunk;

  }
  // remove freeObject from free lsit
  remove_from_freelist(freeObject);


  // CHECKS IF CAN BE SPLIT: get the size of freeObject and subtract by requested size by user + header
  size_t remainderSize = get_size(freeObject) - totalSize;

  // SPLITS: is remainder size bigger than 16 bytes
  if (remainderSize >= sizeof(header)) {

    // set allocated object as addy allocated part of freeObject
    header *allocatedObject = (header *)((char *)freeObject + remainderSize);
    set_size_and_state(allocatedObject, totalSize, ALLOCATED);

    // LEFT SIZE OF ALLOCATED OBJECT: updated as the remainder size
    allocatedObject->left_size = remainderSize;
    set_size_and_state(freeObject, remainderSize, UNALLOCATED);

    // LEFT SIZE OF ALLOCATED OBJECT NEIGHBOR: updated
    header *rightNeighbor = get_right_header(allocatedObject);
    rightNeighbor->left_size = get_size(allocatedObject);

    // get index for the remainder for the free list and insert
    int remainderList = get_index_for_size(remainderSize);
    insert_into_freelist(&freelistSentinels[remainderList], freeObject);

    // return pointer touser-accessible portion of the allocated memory block
    return (header *)((char *)allocatedObject + ALLOC_HEADER_SIZE);
   
  // NO SPLITTING 
  } else {

    // remove freeObject from free list, set allocated and return user-accessible portion of the allocated memory block
    remove_from_freelist(freeObject);
    set_state(freeObject, ALLOCATED);
    return (header *)((char *)freeObject + ALLOC_HEADER_SIZE);
  }
}

//Helper to get the header from a pointer allocated with malloc
static inline header * ptr_to_header(void * p) {
  return (header *)((char *) p - ALLOC_HEADER_SIZE); //sizeof(header));
}


//Helper to manage deallocation of a pointer returned by the useR 
static inline void deallocate_object(void * p) { // --------------------------------------------------------------
  // TODO implement deallocation
  // checks if the pointer exists, if NULL returns
    if (!p) return;

    // seats block to point to the header of the block
    header* block = ptr_to_header(p);

    // checks block for double free test case
    if(!get_state(block)) {
      printf("Double Free Detected\n");
      #line 577
      assert(false);
      return;
     }

    // set the state of wanted block as UNALLOCATED
    set_state(block, UNALLOCATED);

    // get left and right neighbor of block and size as total size
    header* left_neighbor = get_left_header(block);
    header* right_neighbor = get_right_header(block);
    size_t total_size = get_size(block);

    // CHECK IF LEFT/RIGHT NEIGHBORS ARE FREE and not fenceposts
    bool left_free = left_neighbor && !get_state(left_neighbor) && get_state(left_neighbor) != FENCEPOST;
    bool right_free = right_neighbor && !get_state(right_neighbor) && get_state(right_neighbor) != FENCEPOST;

    
    // FREE LIST INDICES: for left/right neighbor and last free list
    int last_freelist_index = N_LISTS - 1;
    int left_index = left_free ? get_index_for_size(get_size(left_neighbor)) : -1;
    int right_index = right_free ? get_index_for_size(get_size(right_neighbor)) : -1;



    // CASE: LEFT AND RIGHT FREE
    if (left_free && right_free) {

        // get the total size of left, block, and right size and set block as left neighbor 
        total_size = get_size(left_neighbor) + get_size(block) + get_size(right_neighbor);
        block = left_neighbor;

        // CHECKS IF LEFT OR RIGHT INDEX IS THE LAST INDEX: if so remove only right block because we are already in last index and right isnt
        if (left_index == last_freelist_index || right_index == last_freelist_index) {
            remove_from_freelist(right_neighbor);

        // IF BOTH ARE NOT IN THE LAST FREE LIST, remove bothand insert into the correct new list    
        } else {
            remove_from_freelist(left_neighbor);
            remove_from_freelist(right_neighbor);
            int coalesced_index = get_index_for_size(total_size);
            insert_into_freelist(&freelistSentinels[coalesced_index], block);
        }
        
    // COALESCE
    // CASE: LEFT IS FREE
    } else if (left_free) {

        // get the total size of the left and current block and set block to addy of left neighbor
        total_size = get_size(left_neighbor) + get_size(block);
        block = left_neighbor;

        // if the left index is not in the last free list
        if (left_index != last_freelist_index) {

            // remove left from free list and set the index of the combined left and current block and insert into freelist
            remove_from_freelist(left_neighbor);
            int coalesced_index = get_index_for_size(total_size);
            insert_into_freelist(&freelistSentinels[coalesced_index], block);
        }

    // CASE: RIGHT IS FREE
    } else if (right_free) {
        
        // get the total size by adding the right block adn current block
        total_size = get_size(block) + get_size(right_neighbor);

        // LAST INDEX: if right block is in the last index
        if (right_index == last_freelist_index) {

            // Replace the right block with the new coalesced block in the last freelist
            remove_from_freelist(right_neighbor);
            insert_into_freelist(&freelistSentinels[last_freelist_index], block);

        // NOT IN LAST INDEX: remove right neighbor from freelist, get new index for combinded size and add to freelist
        } else {
            remove_from_freelist(right_neighbor);
            int coalesced_index = get_index_for_size(total_size);
            insert_into_freelist(&freelistSentinels[coalesced_index], block);
        }

    //CASE: BOTH ALLOCATE LEFT AND RIGHT
    } else {

        // add current block into free list
        int list_index = get_index_for_size(get_size(block));
        insert_into_freelist(&freelistSentinels[list_index], block);
    }

    // set size total size and mark unallocated
    set_size_and_state(block, total_size, UNALLOCATED);

    // UPDATE RIGHT NEIGHBOR LEFT SIZE to total size (if combined)
    right_neighbor = get_right_header(block);
    if (right_neighbor) {
        right_neighbor->left_size = total_size;
    }
}

 // HELPER: Removes an object from the free list
 static void remove_from_freelist(header *block) {
    block->prev->next = block->next;
    block->next->prev = block->prev;
}


//HELPER: Gets the correct index of the free list to insert the object into it
static int get_index_for_size(size_t size) {
  const int SIZE_CLASS = 8; // 8-byte increments
  size_t allocable = size - ALLOC_HEADER_SIZE;
    
  int index = (allocable > 0) ? 
               ((allocable - 1) / SIZE_CLASS) : 
               0;
    
  return (index < N_LISTS - 1) ? index : N_LISTS - 1;
}


 //HELPER: insert object into free list
static void insert_into_freelist(header *freelist, header *block) {
    block->next = freelist->next;
    block->prev = freelist;
    freelist->next->prev = block;
    freelist->next = block;
}

// HELPER: to verify that there are no unlinked previous or next pointers in the free list
static inline header * verify_pointers() {
  for (int i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    for (header * cur = freelist->next; cur != freelist; cur = cur->next) {
      if (cur->next->prev != cur || cur->prev->next != cur) {
        return cur;
      }
    }
  }
  return NULL;
}

// HELPER: Verify the structure of the free list is correct by checking for cycles and misdirected pointers
static inline bool verify_freelist() {
  header * cycle = detect_cycles();
  if (cycle != NULL) {
    fprintf(stderr, "Cycle Detected\n");
    print_sublist(print_object, cycle->next, cycle);
    return false;
  }

  header * invalid = verify_pointers();
  if (invalid != NULL) {
    fprintf(stderr, "Invalid pointers\n");
    print_object(invalid);
    return false;
  }

  return true;
}

// Helper to verify that the sizes in a chunk from the OS are correct and that allocated node'svalues are correct 
static inline header * verify_chunk(header * chunk) {
	if (get_state(chunk) != FENCEPOST) {
		fprintf(stderr, "Invalid fencepost\n");
		print_object(chunk);
		return chunk;
	}
	
	for (; get_state(chunk) != FENCEPOST; chunk = get_right_header(chunk)) {
		if (get_size(chunk)  != get_right_header(chunk)->left_size) {
			fprintf(stderr, "Invalid sizes\n");
			print_object(chunk);
			return chunk;
		}
	}
	
	return NULL;
}

/**
 *   For each chunk allocated by the OS verify that the boundary tags
 *        are consistent
 */
static inline bool verify_tags() {
  for (size_t i = 0; i < numOsChunks; i++) {
    header * invalid = verify_chunk(osChunkList[i]);
    if (invalid != NULL) {
      return invalid;
    }
  }

  return NULL;
}

/**
 *   Initialize mutex lock and prepare an initial chunk of memory for allocation
 */
static void init() {
  // Initialize mutex for thread safety
  pthread_mutex_init(&mutex, NULL);

  #ifdef DEBUG
    // Manually set printf buffer so it won't call malloc when debugging the allocator
    setvbuf(stdout, NULL, _IONBF, 0);
  #endif // DEBUG
  
  // Allocate the first chunk from the OS
  header * block = allocate_chunk(ARENA_SIZE);

  header * prevFencePost = get_header_from_offset(block, -ALLOC_HEADER_SIZE);
  insert_os_chunk(prevFencePost);

  lastFencePost = get_header_from_offset(block, get_size(block));

  // Set the base pointer to the beginning of the first fencepost in the first
  // chunk from the OS
  base = ((char *) block) - ALLOC_HEADER_SIZE; //sizeof(header);

  // Initialize freelist sentinels
  for (int i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    freelist->next = freelist;
    freelist->prev = freelist;
  }

  // Insert first chunk into the free list
  header * freelist = &freelistSentinels[N_LISTS - 1];
  freelist->next = block;
  freelist->prev = block;
  block->next = freelist;
  block->prev = freelist;
}

/* 
 * External interface
 */
void * my_malloc(size_t size) {
  pthread_mutex_lock(&mutex);
  header * hdr = allocate_object(size); 
  pthread_mutex_unlock(&mutex);
  return hdr;
}
void my_free(void * p) {
  pthread_mutex_lock(&mutex);
  deallocate_object(p);
  pthread_mutex_unlock(&mutex);
}

static inline bool is_sentinel(void * p) {
  for (int i = 0; i < N_LISTS; i++) {
    if (&freelistSentinels[i] == p) {
      return true;
    }
  }
  return false;
}
