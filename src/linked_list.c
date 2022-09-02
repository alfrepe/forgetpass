#include "util.h"
#include "linked_list.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

struct list *add_new_entry(const char *fileName, time_t modified) {

    struct list *new = xmalloc(sizeof(struct list));
    new->file = my_strdup(fileName);
    new->last_modified = modified;
    new->next = NULL;
    return new;
}

void insert_at_end(struct list **head, struct list *data) {
    while(*head)  {
        head = &(*head)->next;
    }
    data->next = *head;
    *head = data;
}

struct list *next_element(struct list **head) {
    struct list *temp = *head;
    *head = (*head)->next;
    return temp;
}

void delete_list(struct list **head) {
    while(*head) {
        struct list *node = next_element(head);
        free(node->file);
        free(node);
    }
}

void sorted_insert(struct list **head_ref, struct list *new_node)
{
    if (head_ref == NULL) return ;
    struct list **cursor = head_ref;
    while (*cursor && (*cursor)->last_modified > new_node->last_modified)
        cursor = &((*cursor)->next);
    new_node->next = *cursor;
    *cursor = new_node;
}
