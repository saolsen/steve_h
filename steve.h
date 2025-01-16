// Single header file library for C.
// * Provides an arena allocator and some data structures that use it.
// * Requires c11 or c23. Tested on gcc and clang on macos and linux.
//   @todo: support mingw64, clang and msvc on windows.
//   @todo: support and test on cosmocc.
//
// * Maintains a (thread local) pool of arenas so they are cheap to acquire and release for
//   temporary allocations.
//   Since all allocations are backed by arenas you don't have to free anything individually, just
//   use an arena that matches the lifetime of the data.
// * Includes data structures like a dynamic array that work well with the arena.
//   * Allows for some optimizations like extending instead of reallocing if the array is on the end
//   of an arena.
// * All lengths are signed.
//   * Makes for less casting when comparing lengths and pointers.
//   * If compiling with -Wconversion you probably have to cast to size_t to call stdlib stuff.

// * Rules of thumb.
//   * If a function returns something that needs to be allocated, it should take an arena to
//   allocate the result on.
//   * You should never return something allocated on an arena that wasn't passed in.
//   * If a function needs to allocate temporary memory,
//     it should acquire its own arena and release it before returning.

// * Things to add.
//   * HashMap.
//   * Pool
//   * Handles

// * Other Ideas
//   * Debug print macros that print to stdout on posix and the debug console on windows (for
//     viewing in raddbg)
//   * Helpers to draw stuff with sixel, supported in windows terminal now so cross platform as far
//     as this lib cares.
//   * A debug mode that tracks memory usage.
//   * Helpers to view these data structures in the debugger.
//     * @note(steve): in clion, you can view a pointer as an array like this.
//         ptr @ len
//       * View an array
//         *(&(arr->e[0])) @ arr->len
//       * View a slice
//         *slc.e @ slc.len
//     * @todo(steve): Document how to do this in raddbg.

#ifndef STEVE_H
#define STEVE_H
// NOLINTBEGIN(modernize-use-nullptr)

#include <stddef.h>
#include <stdint.h>

// @todo(steve): Clean up this block.
// * Make it more obvious which compilers and c versions are supported.
//   The current list is
//   * Linux
//     * gcc (c11 and c23)
//     * clang (c11 and c23)
//     * @todo(steve): Make sure works with musl as well as glibc.
//   * MacOS
//     * gcc (c11 and c23) (Does anybody use this?)
//     * clang (c11 and c23)
//   * Windows
//     * mingw64 (not sure the c versions supported)
//     * clang (c11 and c23)
//     * msvc (c11 and c17)
//   * @todo(steve): Support SDL instead of stdlib for all these platforms.
//   * @todo(steve): Support cosmocc.
//   * @todo(steve): Support zigc.
//   * @todo(steve): Does stuff like tinycc support at least c11? If so maybe support those too.
// * One block like this should figure out the compiler and set some easier to switch on defines.
//     eg: STEVE_MACOS_CLANG_C23
//   I can maybe look at other projects like sdl to see how they do this.
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 202302L)
#define STATIC_ASSERT(exp) static_assert(exp)
#define THREAD_LOCAL_STATIC thread_local static
#elif defined(__GNUC__) || defined(__clang__)
#include <assert.h>
#include <stdbool.h>
#define STATIC_ASSERT(exp) _Static_assert(exp, #exp)
#define THREAD_LOCAL_STATIC static __thread
#elif defined(_MSC_VER)
#define THREAD_LOCAL_STATIC __declspec(thread)
#define STATIC_ASSERT(exp) static_assert(exp, #exp)
#else
#error "Unsupported Compiler"
#endif

#define MIN(x, y) ((x) <= (y) ? (x) : (y))
#define MAX(x, y) ((x) >= (y) ? (x) : (y))
#define CLAMP_MAX(x, max) MIN(x, max)
#define CLAMP_MIN(x, min) MAX(x, min)
#define IS_POW2(x) (((x) != 0) && ((x) & ((x) - 1)) == 0)
#define ALIGN_DOWN(n, a) ((n) & ~((a) - 1))
#define ALIGN_UP(n, a) ALIGN_DOWN((n) + (a) - 1, (a))
#define ALIGN_DOWN_PTR(p, a) ((void *)ALIGN_DOWN((ptrdiff_t)(p), (a)))
#define ALIGN_UP_PTR(p, a) ((void *)ALIGN_UP((ptrdiff_t)(p), (a)))

uint64_t pow2_next(uint64_t i) {
    if (i == 0) {
        return 0;
    }
    i--;
    i |= i >> 1;
    i |= i >> 2;
    i |= i >> 4;
    i |= i >> 8;
    i |= i >> 16;
    i |= i >> 32;
    i++;
    return i;
}

// memcpy wrapper so we don't have to include sting.h in the header.
// @todo(steve): Tie in with future error handling.
void *xmemcpy(void *dest, const void *src, ptrdiff_t n);

// Arena
// * An arena is a continuous block of memory that can grow up to a certain size.
// * They currently have a max capacity of 1024*1024 pages. On my m1 mac that's 64GB.
//   This is probably too big. @todo(steve): Make this configurable.
// * There is a thread_local pool of arenas.
//   when they are released their memory is not returned to the operating system,
//   but they are reset and available for use again.
// * This makes arena_acquire a cheap operation so they can be used both for long-lived things
//   and for temporary allocations within a function.
// * Arenas are not thread safe so multiple threads should not use the same arena at the same time.
// * This only works on 64 bit systems where pointers are 64 bits.
STATIC_ASSERT(sizeof(uintptr_t) == 8);

typedef struct Arena Arena;
struct Arena {
    uint8_t *begin;
    uint8_t *pos;
    uint8_t *commit;
    Arena *next_free;
};
// * The way an arena works is it allocates the big block of memory and starts allocations at
//   begin + sizeof(Arena).
// * We want this begin to be aligned to 16 bytes so common things like an array (which is always
//   aligned to 16 bytes here) can be allocated at the start of the arena.
// * Arena happens to be 4 pointers so this works well, static assert here to catch if that changes.
STATIC_ASSERT(sizeof(Arena) % 16 == 0);

// Pool of already allocated arenas that aren't in use. This lets us reuse arenas for small
// (temp/scratch) allocations without having to pass them around or pay the cost of allocating a new
// one each time.
THREAD_LOCAL_STATIC Arena *arena__free_list = NULL;

Arena *arena_acquire(void);
void arena_reset(Arena *arena);
void arena_release(Arena *arena);
void arena_free(Arena *arena);

// Release all the arenas in the pool.
// Not really something you'd use in a real program but useful for testing.
void arena_free_all(void);

#define arena_alloc(arena, type)                                                                   \
    (type *)arena_alloc_size(arena, (ptrdiff_t)sizeof(type), _Alignof(type))
uint8_t *arena_alloc_size(Arena *arena, ptrdiff_t size, ptrdiff_t align);

// Get the size of the arena (not including the arena struct itself).
ptrdiff_t arena_size(Arena *arena);

// You can copy and restore all the data in an area by copying the memory buffer.
// This can be very powerful for cloning arbitrary data structures.
// If you have a data structure you want to clone and it only uses relative pointers, than you
// can dedicate an arena to it and use arena_serialize and arena_deserialize to clone it.
// Buf must have space for arena_size(arena) bytes.
void arena_serialize(void *buf, Arena *arena);
void arena_deserialize(Arena *arena, void *buf, ptrdiff_t size);
// Note that dest comes first which matches the order arena_serialize and memcpy use.
void arena_clone(Arena *dest, Arena *src);

// * It's nice to use relative pointers (offsets from the beginning of the arena) in data structures
//   on an arena.
// * If you store offsets instead of pointers in all the data structures in an arena, and they all
//   only point to other things in the arena, you should use relative pointers if you want to take
//   advantage of the arena_serialize and arena_deserialize.
// * Since the type of the offset is always ptrdiff_t you can't know what this is pointing at from
//   the type.
// * This is annoying, you have to know what it's pointing at from the context.
//   @todo(steve): Is there a better way to do this in c that doesn't suck?
#define rel(arena, ptr) ((ptrdiff_t)(ptr) - (ptrdiff_t)(arena)->begin)
#define ptr(arena, off) (void *)((ptrdiff_t)(arena)->begin + (off))

// Slice
// * A slice is a pointer and a length. It's a view into an array.
// * It's a polymorphic type so you typically typedef it to specific types.
//     eg: typedef Slice(uint8_t) U8Slice;
#define Slice(T)                                                                                   \
    struct {                                                                                       \
        ptrdiff_t len;                                                                             \
        T *e;                                                                                      \
    }

typedef Slice(uint8_t) U8Slice;

// * If the slice is a view into data on an arena, and it's stored in a data structure in the arena,
//   it's better to store a relative slice so the arena can be serialized and deserialized.
// * Since the type of the offset is always ptrdiff_t you can't know what this is pointing at from
//   the type.
//   This is annoying, you have to know what it's pointing at from the context.
//   @todo(steve): Is there a better way to do this in c that doesn't suck?
typedef struct {
    ptrdiff_t len;
    ptrdiff_t e;
} RelSlice;

#define slice_rel(arena, ptr_slice) {.len = (ptr_slice).len, .e = rel(arena, (ptr_slice).e)}
#define slice_ptr(arena, rel_slice) {.len = (rel_slice).len, .e = ptr(arena, (rel_slice).e)}

#define arena_clone_slice(arena, slice)                                                            \
    {.len = (slice).len,                                                                           \
     .e = (typeof((slice).e))arena__clone_slice(arena, (U8Slice *)&(slice),                        \
                                                (ptrdiff_t)sizeof(*((slice).e)))}
uint8_t *arena__clone_slice(Arena *arena, U8Slice *slice, ptrdiff_t item_size);

// Array
// * A dynamic array that grows as needed.
//   It's backed by an arena so you don't have to free it.
// * An array can be resized with helpers like append or setlen.
//   If the new size is > the capacity it will reallocate the data (or extend the data
//   allocation if the array is at the end of the arena).
// * There is no internal pointer in the array struct, so it works when referenced by other data
// structures
//   on the arena using relative pointers.
//   (of course if it reallocs it will move so you'll have to update the reference).
// * It's a polymorphic type so you typically typedef it to specific types.
//     eg: typedef Array(uint8_t) U8Array;
// * Since the type is polymorphic, most of the helper functions are macros.
#define Array(T)                                                                                   \
    struct {                                                                                       \
        ptrdiff_t len;                                                                             \
        ptrdiff_t cap;                                                                             \
        T e[];                                                                                     \
    }

typedef Array(uint8_t) U8Array;

#define arena_alloc_array(arena, type, item_type, cap)                                             \
    (type *)arena__alloc_array(arena, (ptrdiff_t)sizeof(item_type), cap)
U8Array *arena__alloc_array(Arena *arena, ptrdiff_t item_size, ptrdiff_t cap);
U8Array *arena__grow_array(Arena *arena, U8Array *array, ptrdiff_t item_size, ptrdiff_t amount);

#define arr_push(arena, array, val)                                                                \
    arr__maybegrow(arena, array, 1);                                                               \
    (array)->e[(array)->len++] = (val)
#define arr_push_array(arena, array, val)                                                          \
    arr__maybegrow(arena, array, (val)->len);                                                      \
    (xmemcpy(&(array)->e[(array)->len], (val)->e, (val)->len * (ptrdiff_t)sizeof((val)->e[0])),    \
     (array)->len += (val)->len)
#define arr_push_slice(arena, array, slice)                                                        \
    arr__maybegrow(arena, array, (slice).len);                                                     \
    (xmemcpy(&(array)->e[(array)->len], (slice).e, (slice).len * (ptrdiff_t)sizeof((slice).e[0])), \
     (array)->len += (slice).len)
#define arr_setlen(arena, array, n)                                                                \
    assert(n > 0);                                                                                 \
    arr__maybegrow(arena, array, !(array) ? (n) : (n) - (array)->len);                             \
    (array)->len = (n)
#define arr_slice(array) {.len = (array)->len, .e = (array)->e}

// This isn't strictly necessary for the array or arena arguments.
// * For array, you wouldn't push to the result of a function call,
//   That would just throw away the result.
//     eg: arr_push(arena, get_array(), 1);
// * For arena, it'd be bad to pass arena_acquire() because you'd lose the arena reference and leak
//   the whole thing.
//     eg: arr_push(arena_acquire(), a, 1);
// * It is however important for the n argument in case it's something like ++i
//   In that case we don't want to evaluate it twice.
#define arr__maybegrow(arena, array, n)                                                            \
    do {                                                                                           \
        Arena *_arena = (arena);                                                                   \
        typeof(array) _array = (array);                                                            \
        ptrdiff_t _n = (n);                                                                        \
        if (!_array || _array->len + _n > _array->cap) {                                           \
            _array = (typeof(_array))arena__grow_array(_arena, (U8Array *)_array,                  \
                                                       (ptrdiff_t)sizeof(_array->e[0]), _n);       \
            (array) = _array;                                                                      \
        }                                                                                          \
    } while (0)

#define arena_clone_arr(arena, array)                                                              \
    (typeof(array))arena__clone_arr(arena, (U8Array *)(array), (ptrdiff_t)sizeof((array)->e[0]))
U8Array *arena__clone_arr(Arena *arena, U8Array *array, ptrdiff_t item_size);

// Notes on Array vs Slice
// * An array contains the array data, so it's a buffer with metadata. The buffer is almost always
//   in the arena so you typically have pointers to arrays.
// * A slice is a pointer with some metadata. That makes it a fancy pointer so you usually use it as
// a value
//   rather than a pointer to a slice.
// * Many times you'd want to pass an array to a function that takes a slice. Use the slice macro to
//   do that.
// * You can't alter slices, so these functions treat them as const.
//   * There's no slice -> array converter
//     * There's no guarantees about where the data the slice points to is stored so you don't want
//     to modify it.
//     * If you want to pass an array and use it as an array, just pass an array pointer.
//     * If you want to create an array from a slice (by copying the data), you can use
//     arena_push_slice.

// A String is a slice of characters.
// * It's length doesn't include a null terminator and there's no guarantee that there is a null
//   terminator.
//   * When it's a view into another string like in a parser or something, there definitely won't be
//   one.
//   * If it's allocated in an arena with one of the functions here, there usually is a null
//   terminator, because it's easier to inspect in the debugger. But this is not a property you can
//   rely on in code!
// * To pass to stdlib and other functions that expect a null terminated string, you can use the
//   cstr macro.
//   * It will allocate a new buffer in the arena with a null terminator.
//     @opt(steve): Don't allocate if the String already has a null terminator.
// * To get a String view of a c string, use the str macro.
typedef Slice(char) String;

#define str(c_string) ((String){.len = strlen(c_string), .e = c_string})
#define cstr(a, s) arena__alloc_cstring((a), (s))

typedef Array(String) StringArray;
typedef Slice(String) StringSlice;

StringSlice str_split(Arena *a, String s, char sep);

#if 0
// Map
// @todo(steve): hashmaps.
// probably gonna base it on this either
// * jon blow's hashmap: https://gist.github.com/saolsen/25e22c9ec7445acf1a60d484ea357355
// * chris wellon's hashmap: https://nullprogram.com/blog/2023/09/30/

// Interned Strings
// @todo(steve): interned strings.


// Pool
// @todo(steve): pool.
typedef struct Pool Pool;
struct Pool {
    Arena *arena;
    ptrdiff_t len;
    ptrdiff_t cap;
    ptrdiff_t item_size;
    ptrdiff_t next_free_offset;
    void *free_list;
    uint8_t *data;
};
#endif

// NOLINTEND(modernize-use-nullptr)
#endif // STEVE_H

#ifdef STEVE_IMPLEMENTATION
// NOLINTBEGIN(modernize-use-nullptr)

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32

#include <Windows.h>
#include <Memoryapi.h>

// todo(steve): Can I set a pragma or whatever to link kernal32.lib?
//#pragma comment(lib, "kernel32.lib")

ptrdiff_t memory__page_size(void) {
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    return sys_info.dwPageSize;
}

uint8_t *memory__reserve(ptrdiff_t size) {
    void *r = VirtualAlloc(NULL, (size_t)size, MEM_RESERVE, PAGE_READWRITE);
    if (r == NULL) {
        // @todo(steve): Call GetLastError to get the error message.
        perror("memory__reserve");
        exit(1);
    }
    return r;
}

void memory__commit(uint8_t *addr, ptrdiff_t size) {
    // addr should be the start of a page and size should be a multiple of the page size.
    if (VirtualAlloc(addr, (size_t)size, MEM_COMMIT, PAGE_READWRITE) == 0) {
        perror("memory__commit");
        exit(1);
    }
}

void memory__free(uint8_t *addr) {
    if (VirtualFree(addr, 0, MEM_RELEASE) == 0) {
        perror("memory__free");
        exit(1);
    }
}

#else
#include <sys/mman.h>
#include <unistd.h>

ptrdiff_t memory__page_size(void) {
    return sysconf(_SC_PAGE_SIZE);
}

uint8_t *memory__reserve(ptrdiff_t size) {
    void *addr = mmap(NULL, (size_t)cap, PROT_NONE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (addr == MAP_FAILED) {
        perror("memory__reserve");
        exit(1);
    }
    return addr;
}

void memory__commit(uint8_t *addr, ptrdiff_t size) {
    // addr should be the start of a page and size should be a multiple of the page size.
    if (mprotect(addr, size, PROT_READ | PROT_WRITE) == -1) {
        perror("memory__commit");
        exit(1);
    }
}

void memory__free(uint8_t *addr) {

}

#endif

void *xmemcpy(void *dest, const void *src, ptrdiff_t n) {
    assert(n >= 0);
    return memcpy(dest, src, (size_t)n);
}

Arena *arena_acquire(void) {
    if (arena__free_list) {
        Arena *arena = arena__free_list;
        arena__free_list = arena->next_free;
        return arena;
    }

    // Allocate a new arena.
    ptrdiff_t pagesize = memory__page_size(); // 16kb on my machine.
    assert(pagesize >= 0);
    ptrdiff_t cap =
        pagesize * 4 * 1024 * 1024; // 64GB on my machine. @note(steve): probably way too much
    assert(cap >= 0);

    // VirtualAlloc(null, size, MEM_RESERVE, PAGE_READWRITE);
    uint8_t *addr = memory__reserve(cap);
    // commit first page
    memory__commit(addr, pagesize);

    Arena *arena = (Arena *)addr;
    arena->begin = (uint8_t *)(addr);
    arena->pos = (uint8_t *)(addr) + sizeof(*arena);
    arena->commit = (uint8_t *)(addr) + pagesize;
    return arena;
}

void arena_reset(Arena *arena) {
    arena->pos = arena->begin + sizeof(*arena);
}

void arena_release(Arena *arena) {
    // @opt(steve): If we have a lot of pages committed, we could free it
    //   and then create a new virtual allocation the next time it's used.
    //   On windows, you can "uncommit" pages but not on posix.
    // @todo(steve): windows
    //
    arena_reset(arena);
    arena->next_free = arena__free_list;
    arena__free_list = arena;
}

void arena_free(Arena *arena) {

    memory__free(arena->begin);
}

void arena_free_all(void) {
    Arena *arena = arena__free_list;
    while (arena) {
        Arena *next = arena->next_free;
        arena_free(arena);
        arena = next;
    }
    arena__free_list = NULL;
}

uint8_t *arena_alloc_size(Arena *arena, ptrdiff_t size, ptrdiff_t align) {
    // Align Pointer
    uint8_t *start = (uint8_t *)ALIGN_UP_PTR(arena->pos, align);
    uint8_t *new_pos = start + size;

    // Commit new page if needed.
    if (new_pos > arena->commit) {
        uint8_t *new_commit = arena->commit;
        ptrdiff_t pagesize = memory__page_size();
        while (new_pos > new_commit) {
            new_commit += pagesize;
        }
        memory__commit(arena->commit, new_commit - arena->commit);
        arena->commit = new_commit;
    }
    arena->pos = new_pos;
    return start;
}

// The size of the data in the arena. This is the size of buffer you would need to call
// arena_serialize.
ptrdiff_t arena_size(Arena *arena) {
    return arena->pos - arena->begin - (ptrdiff_t)sizeof(Arena);
}

void arena_serialize(void *buf, Arena *arena) {
    xmemcpy(buf, arena->begin + sizeof(Arena), arena_size(arena));
}

// Note: This only works on an empty arena, if the arena passed in is not empty it will get reset.
// @todo(steve): Return an error or something instead of just resetting the arena.
void arena_deserialize(Arena *arena, void *buf, ptrdiff_t size) {
    arena_reset(arena);
    uint8_t *data = arena_alloc_size(arena, size, 1);
    xmemcpy(data, buf, size);
}

void arena_clone(Arena *dest, Arena *src) {
    ptrdiff_t size = arena_size(src);
    arena_deserialize(dest, src->begin + sizeof(Arena), size);
}

uint8_t *arena__clone_slice(Arena *arena, U8Slice *slice, ptrdiff_t item_size) {
    uint8_t *buf = arena_alloc_size(arena, slice->len * item_size, 16);
    xmemcpy(buf, slice->e, slice->len * item_size);
    return buf;
}

U8Array *arena__alloc_array(Arena *arena, ptrdiff_t item_size, ptrdiff_t cap) {
    U8Array *array =
        (U8Array *)arena_alloc_size(arena, (ptrdiff_t)sizeof(U8Array) + item_size * cap, 16);
    array->len = 0;
    array->cap = cap;
    return array;
}

U8Array *arena__grow_array(Arena *arena, U8Array *array, ptrdiff_t item_size, ptrdiff_t amount) {
    if (array == NULL) {
        return arena__alloc_array(arena, item_size, MAX(4, amount));
    }
    ptrdiff_t new_cap = MAX(array->cap, 4);
    while (MAX(array->cap, array->len) + amount > new_cap) {
        new_cap *= 2;
    }
    if (new_cap > array->cap) {
        // Grow the array
        if (arena->pos == (uint8_t *)(array->e) + array->cap * item_size) {
            // Array is on the end of the arena, we can just grow it.
            arena_alloc_size(arena, (new_cap - array->cap) * item_size, 1);
            array->cap = new_cap;
            return array;
        } else {
            // Array is not on the end of the arena, we need a new allocation.
            U8Array *new_array = arena__alloc_array(arena, item_size, new_cap);
            new_array->len = array->len;
            xmemcpy(new_array->e, array->e, new_array->len * item_size);
            return new_array;
        }
    }
    return array;
}

U8Array *arena__clone_arr(Arena *arena, U8Array *array, ptrdiff_t item_size) {
    U8Array *new_array = arena__alloc_array(arena, item_size, array->len);
    new_array->len = array->len;
    xmemcpy(new_array->e, array->e, new_array->len * item_size);
    return new_array;
}

char *arena__alloc_cstring(Arena *a, String *s) {
    char *c = (char *)arena_alloc_size(a, s->len + 1, _Alignof(char));
    xmemcpy(c, s->e, s->len);
    c[s->len] = '\0';
    return c;
}

String format(Arena *a, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    va_list args_copy;
    va_copy(args_copy, args);
    ptrdiff_t len = vsnprintf(NULL, 0, fmt, args_copy);
    va_end(args_copy);
    char *c = (char *)arena_alloc_size(a, len + 1, _Alignof(char));
    vsnprintf(c, (size_t)len + 1, fmt, args);
    va_end(args);
    return (String){.len = len, .e = c};
}

StringSlice str_split(Arena *a, String s, char sep) {
    // Skip leading separators.
    int i = 0;
    StringArray *parts = NULL;
    while (i < s.len) {
        int start = i;
        while (i < s.len && s.e[i] != sep) {
            i++;
        }
        if (i > start) {
            String part = {.len = i - start, .e = s.e + start};
            arr_push(a, parts, part);
        }
        while (i < s.len && s.e[i] == sep) {
            i++;
        }
    }
    if (parts == NULL) {
        return (StringSlice){.len = 0, .e = NULL};
    }
    StringSlice result = arr_slice(parts);
    return result;
}

// NOLINTEND(modernize-use-nullptr)
#endif // STEVE_IMPLEMENTATION

#ifdef STEVE_TEST
// NOLINTBEGIN(modernize-use-nullptr)

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_helpers(void);
static void test_arena_acquire_release(void);
static void test_arena_reset(void);
static void test_arena_free(void);
static void test_arena_alloc_alignment(void);
static void test_arena_large_alloc(void);
static void test_rel_ptr(void);
static void test_slices(void);
static void test_rel_slices(void);
static void test_dynamic_arrays(void);
static void test_arena_serialize(void);
static void test_strings(void);

int main(void) {
    test_helpers();
    test_arena_acquire_release();
    test_arena_reset();
    test_arena_free();
    test_arena_alloc_alignment();
    test_arena_large_alloc();
    test_rel_ptr();
    test_slices();
    test_rel_slices();
    test_dynamic_arrays();
    test_arena_serialize();
    test_strings();

    printf("steve.h: All tests passed!\n");
    return 0;
}

static void test_helpers(void) {
    assert(pow2_next(0) == 0);
    assert(pow2_next(1) == 1);
    assert(pow2_next(2) == 2);
    assert(pow2_next(3) == 4);
    assert(pow2_next(4) == 4);
    assert(pow2_next(5) == 8);
    assert(pow2_next(7) == 8);
    assert(pow2_next(8) == 8);
    assert(pow2_next(9) == 16);
    assert(pow2_next(63) == 64);
    assert(pow2_next(64) == 64);
    assert(pow2_next(65) == 128);

    assert(MIN(10, 20) == 10);
    assert(MIN(-5, 3) == -5);
    assert(MAX(10, 20) == 20);
    assert(MAX(-5, 3) == 3);

    assert(CLAMP_MAX(25, 20) == 20); // 25 clamped to 20
    assert(CLAMP_MAX(15, 20) == 15); // within limit
    assert(CLAMP_MIN(-1, 0) == 0);   // -1 clamped to 0
    assert(CLAMP_MIN(10, 0) == 10);  // within limit

    assert(IS_POW2(1) == true);
    assert(IS_POW2(2) == true);
    assert(IS_POW2(3) == false);
    assert(IS_POW2(4) == true);
    assert(IS_POW2(0) == false); // Edge case: 0 is not a power of 2

    assert(ALIGN_UP(0, 8) == 0);
    assert(ALIGN_UP(1, 8) == 8);
    assert(ALIGN_UP(7, 8) == 8);
    assert(ALIGN_UP(8, 8) == 8);
    assert(ALIGN_UP(9, 8) == 16);

    assert(ALIGN_DOWN(0, 8) == 0);
    assert(ALIGN_DOWN(7, 8) == 0);
    assert(ALIGN_DOWN(8, 8) == 8);
    assert(ALIGN_DOWN(9, 8) == 8);
    assert(ALIGN_DOWN(15, 8) == 8);

    {
        uintptr_t ptr_val = 15;
        void *p1 = (void *)ptr_val;
        void *aligned_up = ALIGN_UP_PTR(p1, 8);
        void *aligned_down = ALIGN_DOWN_PTR(p1, 8);
        assert((uintptr_t)aligned_up == 16);
        assert((uintptr_t)aligned_down == 8);
    }
}

static void test_arena_acquire_release(void) {
    // Acquire a single arena and release it
    Arena *a = arena_acquire();
    assert(a != NULL);
    arena_release(a);

    // Acquire multiple arenas
    Arena *a1 = arena_acquire();
    Arena *a2 = arena_acquire();
    assert(a1 != NULL && a2 != NULL);
    arena_release(a1);
    arena_release(a2);

    // Acquire again to ensure reuse
    Arena *a3 = arena_acquire();
    assert(a3 == a1 || a3 == a2); // Freed arenas should be reused.
    arena_release(a3);
    arena_free_all();
}

static void test_arena_reset(void) {
    Arena *a = arena_acquire();
    // Allocate some memory
    int *x = arena_alloc(a, int);
    *x = 42;
    assert(*x == 42);

    // Reset
    arena_reset(a);
    assert(arena_size(a) == 0);

    // Allocate again after reset
    int *y = arena_alloc(a, int);
    *y = 2025;
    assert(*y == 2025);

    // Pointers should be to the same memory.
    assert(y == x);
    arena_release(a);
    arena_free_all();
}

static void test_arena_free(void) {
    Arena *a = arena_acquire();
    int *x = arena_alloc(a, int);
    *x = 123;
    arena_free(a); // Should succeed without error.

    // Also test arena_free_all
    Arena *a1 = arena_acquire();
    Arena *a2 = arena_acquire();
    arena_release(a1);
    arena_release(a2);
    arena_free_all();
    assert(arena__free_list == NULL);

    Arena *a3 = arena_acquire();
    arena_release(a3);
    arena_free_all();
}

static void test_arena_alloc_alignment(void) {
    Arena *a = arena_acquire();

    // Test alignment for 1, 2, 4, 16
    ptrdiff_t alignments[] = {1, 2, 4, 16};
    for (int i = 0; i < 4; i++) {
        ptrdiff_t align = alignments[i];
        uint8_t *p = arena_alloc_size(a, 10, align);
        assert(((ptrdiff_t)p % align) == 0 && "Pointer must be aligned");
    }

    // Cross page boundary test
    ptrdiff_t pagesize = memory__page_size();
    (void)arena_alloc_size(a, pagesize + 1, 16);

    arena_release(a);
    arena_free_all();
}

static void test_arena_large_alloc(void) {
    Arena *a = arena_acquire();
    ptrdiff_t pagesize = memory__page_size();
    ptrdiff_t big_size = pagesize * 5;
    void *big_block = arena_alloc_size(a, big_size, 16);
    assert(big_block != NULL);
    // Mke sure we can write to it.
    memset(big_block, 0xAB, (size_t)big_size);

    arena_release(a);
    arena_free_all();
}

static void test_rel_ptr(void) {
    Arena *a = arena_acquire();
    int *x = arena_alloc(a, int);
    *x = 55;
    ptrdiff_t offset = rel(a, x);
    int *y = (int *)ptr(a, offset);
    assert(x == y);
    assert(*y == 55);

    arena_release(a);
    arena_free_all();
}

static void test_slices(void) {
    Arena *a = arena_acquire();

    // Create an array
    typedef Array(int) IntArray;
    IntArray *arr = NULL;
    for (int i = 0; i < 5; i++) {
        arr_push(a, arr, i * 10);
    }

    // Turn into slice
    typedef Slice(int) IntSlice;
    IntSlice s = arr_slice(arr);
    assert(s.len == 5);
    for (int i = 0; i < 5; i++) {
        assert(s.e[i] == i * 10);
    }

    // Clone slice
    Arena *a2 = arena_acquire();
    IntSlice clone = arena_clone_slice(a2, s);
    assert(clone.len == s.len);
    for (int i = 0; i < 5; i++) {
        assert(clone.e[i] == s.e[i]);
    }
    // Mutate original
    s.e[0] = 999;
    // Cloned slice remains unaffected
    assert(clone.e[0] == 0);

    arena_release(a);
    arena_release(a2);
    arena_free_all();
}

static void test_rel_slices(void) {
    Arena *a = arena_acquire();

    // Create an array
    typedef Array(int) IntArray;
    IntArray *arr = NULL;
    for (int i = 0; i < 5; i++) {
        arr_push(a, arr, i * 10);
    }

    // Turn into slice
    typedef Slice(int) IntSlice;
    IntSlice s = arr_slice(arr);
    assert(s.len == 5);
    for (int i = 0; i < 5; i++) {
        assert(s.e[i] == i * 10);
    }

    // Turn into relative slice
    RelSlice rs = slice_rel(a, s);
    assert(rs.len == 5);

    // Turn back into slice
    IntSlice s2 = slice_ptr(a, rs);
    assert(s2.len == 5);
    for (int i = 0; i < 5; i++) {
        assert(s2.e[i] == i * 10);
    }

    arena_release(a);
    arena_free_all();
}

static void test_dynamic_arrays(void) {
    typedef Array(int) IntArray;
    typedef Slice(int) IntSlice;

    Arena *a = arena_acquire();

    // alloc_array
    IntArray *arr = arena_alloc_array(a, IntArray, int, 15);
    assert(arr->len == 0);
    assert(arr->cap == 15);

    // Push elements
    arr = NULL;
    for (int i = 0; i < 10; i++) {
        arr_push(a, arr, i);
        assert(arr->len == i + 1);
        for (int j = 0; j <= i; j++) {
            assert(arr->e[j] == j);
        }
    }

    // Force reallocation
    // The library starts with capacity=4 if we push many items, we ensure multiple grows.
    for (int i = 0; i < 100; i++) {
        arr_push(a, arr, i + 100);
    }
    assert(arr->len == 110);

    // arr_push_slice
    IntSlice slice = {.len = 3, .e = (int[]){999, 1000, 1001}};
    arr_push_slice(a, arr, slice);
    assert(arr->len == 113);
    assert(arr->e[110] == 999);
    assert(arr->e[111] == 1000);
    assert(arr->e[112] == 1001);

    // setlen
    // Length that puts us on a new page so that we know it worked if we can write to the end.
    ptrdiff_t pagesize = memory__page_size();
    arr_setlen(a, arr, pagesize + 200);
    assert(arr->len == pagesize + 200);
    arr->e[pagesize + 199] = 1234;

    // clone_array
    Arena *a2 = arena_acquire();
    IntArray *clone = arena_clone_arr(a2, arr);
    assert(clone->len == arr->len);
    for (int i = 0; i < (int)arr->len; i++) {
        assert(clone->e[i] == arr->e[i]);
    }

    arena_release(a);
    arena_release(a2);
    arena_free_all();
}

static void test_arena_serialize(void) {
    // @todo(steve): Test relative pointers and relative slices here.
    Arena *a = arena_acquire();
    typedef Array(int) IntArray;
    typedef Slice(int) IntSlice;
    IntArray *arr = NULL;
    for (int i = 0; i < 10; i++) {
        arr_push(a, arr, i * 10);
    }
    ptrdiff_t arr_rel = rel(a, arr);
    IntSlice s = arr_slice(arr);
    RelSlice s_rel = slice_rel(a, s);

    ptrdiff_t size = arena_size(a);
    void *buf = malloc((size_t)size);
    arena_serialize(buf, a);

    // Deserialize
    Arena *copy = arena_acquire();
    arena_deserialize(copy, buf, size);

    // Check data
    IntArray *arr_copy = ptr(copy, arr_rel);
    IntSlice s_copy = slice_ptr(copy, s_rel);
    assert(arr_copy != arr);
    assert((ptrdiff_t)arr_copy >= (ptrdiff_t)copy->begin);
    assert((ptrdiff_t)arr_copy <= (ptrdiff_t)copy->begin + size);
    assert(s_copy.len == 10);
    assert(s_copy.e == arr_copy->e);
    assert(arr_copy->len == 10);
    for (int i = 0; i < 10; i++) {
        assert(arr_copy->e[i] == i * 10);
        assert(s_copy.e[i] == i * 10);
    }
    free(buf);

    Arena *copy2 = arena_acquire();
    arena_clone(copy2, a);
    arr_copy = ptr(copy2, arr_rel);
    IntSlice s_copy2 = slice_ptr(copy2, s_rel);
    assert(arr_copy != arr);
    assert((ptrdiff_t)arr_copy >= (ptrdiff_t)copy2->begin);
    assert((ptrdiff_t)arr_copy <= (ptrdiff_t)copy2->begin + size);
    assert(s_copy2.len == 10);
    assert(s_copy2.e == arr_copy->e);
    assert(arr_copy->len == 10);
    for (int i = 0; i < 10; i++) {
        assert(arr_copy->e[i] == i * 10);
        assert(s_copy2.e[i] == i * 10);
    }

    arena_release(a);
    arena_release(copy);
    arena_release(copy2);
    arena_free_all();
}

static void test_strings(void) {
    Arena *a = arena_acquire();

    // format
    String s1 = format(a, "Hello %d %s", 42, "World");
    assert(s1.len == 14);
    assert(strncmp(s1.e, "Hello 42 World", (size_t)s1.len) == 0);

    // split
    String s2 = str("apple,banana,cherry");
    StringSlice parts = str_split(a, s2, ',');
    assert(parts.len == 3);
    assert(strncmp(parts.e[0].e, "apple", (size_t)parts.e[0].len) == 0);
    assert(strncmp(parts.e[1].e, "banana", (size_t)parts.e[1].len) == 0);
    assert(strncmp(parts.e[2].e, "cherry", (size_t)parts.e[2].len) == 0);

    String s3 = str(",banana,cherry");
    parts = str_split(a, s3, ',');
    assert(parts.len == 2);
    assert(strncmp(parts.e[0].e, "banana", (size_t)parts.e[1].len) == 0);
    assert(strncmp(parts.e[1].e, "cherry", (size_t)parts.e[2].len) == 0);

    String s4 = str("banana,cherry,");
    parts = str_split(a, s4, ',');
    assert(parts.len == 2);
    assert(strncmp(parts.e[0].e, "banana", (size_t)parts.e[1].len) == 0);
    assert(strncmp(parts.e[1].e, "cherry", (size_t)parts.e[2].len) == 0);

    String s5 = str(",");
    parts = str_split(a, s5, ',');
    assert(parts.len == 0);

    String s6 = str(",,,,,");
    parts = str_split(a, s6, ',');
    assert(parts.len == 0);

    // cstr
    char *c = cstr(a, &s2);
    assert(strcmp(c, "apple,banana,cherry") == 0);

    arena_release(a);
    arena_free_all();
}

// NOLINTEND(modernize-use-nullptr)
#endif // STEVE_TEST
