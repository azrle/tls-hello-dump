#include "inet_hashtable.h"
#include <stdio.h>

static void fl_gen_n_nodes(struct free_list *fl, u_int n) {
    if (n <= 0) return;
    if (fl->size + n > fl->max_size)
        n = fl->max_size - fl->size;

    struct node *head = malloc(sizeof(struct node) * n),
                *tail = head;
    int i;
    for (i = 0; i < n - 1; ++i) {
        tail->next = tail + 1;
        tail = tail->next;
    }
    tail->next = fl->list->next;
    fl->size += n;
    fl->list->next = head;
}

struct free_list *
fl_init(u_int size, u_int max_fl_size) {
    if (size < 1) return NULL;

    struct free_list *fl = NULL;
    if ( (fl = malloc(sizeof(struct free_list))) == NULL ) {
        return NULL;
    }
    if ( (fl->list = init_list()) == NULL ) {
        return NULL;
    }
    fl->list->next = NULL;
    fl->max_size = max_fl_size;
    if (size > fl->max_size)
        size = fl->max_size;

    fl_gen_n_nodes(fl, size);

    return fl;
}

void
fl_free_node(
        struct free_list *fl,
        struct node *node
) {
    if (fl->list) {
        node->next = fl->list->next;
        fl->list->next = node;
    }
}

struct node *
fl_get_node(
        struct free_list *fl
) {
    struct node *node = NULL;
    u_int n;
    if (fl->list) {
        node = fl->list->next;
        if (node == NULL) {
            n = MIN(fl->size, fl->max_size - fl->size);
            fl_gen_n_nodes(fl, n);
            node = fl->list->next;
        }
        if (node == NULL) {
            fprintf(stderr, "No free node. Current size: %u\n", fl->size);
            return NULL;
        }

        fl->list->next = node->next;
        node->next = NULL;
    }
    return node;
}

struct hashtable *
ht_init(u_int size) {
    if (size < 1) return NULL;

    struct hashtable *ht = NULL;
    if ( (ht = malloc(sizeof(struct hashtable))) == NULL ) {
        return NULL;
    }

    ht->size = 0;
    if ( (ht->table = malloc(sizeof(struct head *) * size) ) == NULL ) {
        return NULL;
    }

    int i;
    for (i=0; i<size; ++i) {
        if ( (ht->table[i] = init_list()) == NULL ) {
            return NULL;
        }
        ht->table[i]->next = NULL;
    }

    ht->size = size;

    return ht;
}

struct node *
ht_get(
        struct hashtable *ht,
        u_int laddr, u_int faddr,
        u_short lport, u_short fport
) {
    u_int hash = hash_3words( laddr, faddr, ((u_int)lport)<<16 | (u_int)fport );
    struct node *ptr = NULL;
    for (ptr = ht->table[hash & (ht->size - 1)]->next; ptr; ptr = ptr->next) {
        if (ptr->laddr == laddr && ptr->faddr == faddr &&
                ptr->lport == lport && ptr->fport == fport) {
            return ptr;
        }
    }
    return NULL;
}

struct node *
ht_remove(
        struct free_list *fl,
        struct hashtable *ht,
        u_int laddr, u_int faddr,
        u_short lport, u_short fport
) {
    u_int hash = hash_3words( laddr, faddr, ((u_int)lport)<<16 | (u_int)fport );
    struct head *head = ht->table[hash & (ht->size - 1)];
    struct node *pre = NULL,
                *ptr = head->next;

    struct node *ret = NULL;
    while (ptr) { /* remove all matched results */
        if (ptr->laddr == laddr && ptr->faddr == faddr &&
                ptr->lport == lport && ptr->fport == fport) {
            if (pre == NULL) {
                head->next = ptr->next;
            } else {
                pre->next = ptr->next;
            }
            fl_free_node(fl, ptr);
            ret = ptr;
        } else {
            pre = ptr;
        }
        ptr = pre==NULL ? head->next : pre->next;
    }
    return ret;
}

void
ht_insert(
        struct free_list *fl,
        struct hashtable *ht,
        u_int laddr, u_int faddr,
        u_short lport, u_short fport,
        u_short proto_version, u_short hello_version,
        u_short cipher_len, const u_char* ciphers
) {
    struct node *ptr = fl_get_node(fl);
    if (ptr == NULL)
        return; /* silently ignore */

    u_int hash = hash_3words( laddr, faddr, ((u_int)lport)<<16 | (u_int)fport);
    u_int slot = hash & (ht->size - 1);

    ptr->laddr = laddr; ptr->faddr = faddr;
    ptr->lport = lport; ptr->fport = fport;
    ptr->proto_version = proto_version;
    ptr->hello_version = hello_version;
    ptr->cipher_len = cipher_len;
    memcpy(ptr->ciphers, ciphers, cipher_len);
    ptr->next = ht->table[slot]->next;
    ht->table[slot]->next = ptr;
}
