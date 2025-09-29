#include "linked_list.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>


   linked_list *ll_create(void) {
        linked_list *ll = (linked_list *)malloc(sizeof(linked_list));
        if (!ll) return NULL;
        ll->head = NULL;
        ll->tail = NULL;
        ll->size = 0;
        return ll;
    }

    void ll_free(linked_list *ll) {
        if (!ll) return;
        linked_list_node *current = ll->head;
        while (current) {
            linked_list_node *next = current->next;
            free(current);
            current = next;
        }
        free(ll);
    }

    int ll_append(linked_list *ll, void *data) {
        if (!ll) return -1;
        linked_list_node *node = (linked_list_node *)malloc(sizeof(linked_list_node));
        if (!node) return -1;
        node->data = data;
        node->next = NULL;
        if (ll->tail) {
            ll->tail->next = node;
            ll->tail = node;
        } else {
            ll->head = node;
            ll->tail = node;
        }
        ll->size++;
        return 0;
    }

    int ll_prepend(linked_list *ll, void *data) {
        if (!ll) return -1;
        linked_list_node *node = (linked_list_node *)malloc(sizeof(linked_list_node));
        if (!node) return -1;
        node->data = data;
        node->next = ll->head;
        ll->head = node;
        if (!ll->tail) {
            ll->tail = node;
        }
        ll->size++;
        return 0;
    }

    void *ll_pop_front(linked_list *ll) {
        if (!ll || !ll->head) return NULL;
        linked_list_node *node = ll->head;
        void *data = node->data;
        ll->head = node->next;
        if (!ll->head) {
            ll->tail = NULL;
        }
        free(node);
        ll->size--;
        return data;
    }

    size_t ll_size(const linked_list *ll) {
        return ll ? ll->size : 0;
    }
    int ll_is_empty(const linked_list *ll) {
        return ll ? (ll->size == 0) : 1;
    }