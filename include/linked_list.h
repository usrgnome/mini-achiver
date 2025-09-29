#ifndef LINKED_LIST_H
#define LINKED_LIST_H

#include <stddef.h>  /* size_t */

/* ============================================================
   Singly linked list (generic)
   ============================================================ */

typedef struct linked_list_node {
    void *data;
    struct linked_list_node *next;
} linked_list_node;

typedef struct linked_list {
    linked_list_node *head;
    linked_list_node *tail;
    size_t size;
} linked_list;

/* API */
linked_list *ll_create(void);
void ll_free(linked_list *ll);
int ll_append(linked_list *ll, void *data);
int ll_prepend(linked_list *ll, void *data);
void *ll_pop_front(linked_list *ll);
size_t ll_size(const linked_list *ll);
int ll_is_empty(const linked_list *ll);

#endif /* LINKED_LIST_H */
