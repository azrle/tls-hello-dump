#ifndef __INET_HASHTABLE_H__
#define __INET_HASHTABLE_H__

#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

/* free nodes size */
/* 1 node ~= 64.02 KiB */
// #define DEFAULT_INIT_SIZE (1<<10)
#define DEFAULT_INIT_SIZE (1<<10)
#define DEFAULT_MAX_SIZE  (1<<20)
/* hash table size */
#define DEFAULT_HASH_TABLE_SIZE ((1<<16)*2)

/* Length of ciphers data */
#define CIPHER_LENGTH (1<<16)

/* everybody needs food */
#define INITVAL 0xf00d

/* lookup3 */
#define HASH_FINAL(a,b,c) \
{ \
      c ^= b; c -= rol32(b,14); \
      a ^= c; a -= rol32(c,11); \
      b ^= a; b -= rol32(a,25); \
      c ^= b; c -= rol32(b,16); \
      a ^= c; a -= rol32(c,4);  \
      b ^= a; b -= rol32(a,14); \
      c ^= b; c -= rol32(b,24); \
}

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

struct node {
    struct node *next;
    u_int   laddr, faddr;
    u_short lport, fport;
    u_short proto_version, hello_version;
    u_short cipher_len;
    u_char ciphers[CIPHER_LENGTH];
};

struct head {
    struct node *next;
};

struct free_list {
    u_int size;
    u_int max_size;
    struct head *list;
};

struct hashtable {
    u_int size;
    struct head **table;
};

static inline u_int rol32(u_int word, u_int shift) {
    return (word << shift) | (word >> ((-shift) & 31));
}

static inline u_int hash_3words(u_int a, u_int b, u_int c) {
    a += INITVAL;
    b += INITVAL;
    c += INITVAL;
    HASH_FINAL(a, b, c);
    return c;
}

static inline struct head *init_list() {
    return malloc(sizeof(struct head));
}

struct free_list *fl_init(u_int size, u_int max_fl_size);
void   fl_free_node(struct free_list *fl, struct node *node);
struct node * fl_get_node(struct free_list *fl);

struct hashtable * ht_init(u_int size);
struct node * ht_get(struct hashtable *ht, u_int laddr, u_int faddr, u_short lport, u_short fport);
struct node * ht_remove(struct free_list *fl, struct hashtable *ht,
        u_int laddr, u_int faddr, u_short lport, u_short fport);
void   ht_insert(struct free_list *fl, struct hashtable *ht,
        u_int laddr, u_int faddr, u_short lport, u_short fport,
        u_short proto_version, u_short hello_version,
        u_short cipher_len, const u_char* ciphers);
#endif
