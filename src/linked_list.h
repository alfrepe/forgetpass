#pragma once
#include <time.h>

struct list {
    char *file;
    time_t last_modified;
    struct list *next;
};
struct list *start;
struct list *add_new_entry(const char *fileName, time_t modified);
void insert_at_end(struct list **head, struct list *data);
struct list *next_element(struct list **head);
void delete_list(struct list **head);
// orden descendete
void sorted_insert(struct list **head_ref, struct list *new_node);
