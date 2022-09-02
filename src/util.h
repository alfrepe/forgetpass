#pragma once

#include <stdio.h>
#include <stdbool.h>
#include <time.h>

#define FREE_AND_NULL(p) \
    do                   \
    {                    \
        free(p);         \
        (p) = NULL;      \
    } while (0 != 0) // this is a bit hack because the macro must be end with semicolon
    
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define MAX_TIME_SIZE 40

void REPORT_BUG_AND_ABORT(const char *file, int line);
#define BUG() REPORT_BUG_AND_ABORT(__FILE__, __LINE__)

// 0 falso, 1 verdadero (son todo espacios)
int is_all_space(const char *str);
char *delete_newline(char *str);
// Don't forget to call free()!
char *append_str(const char *s1, const char *s2);
void error(const char *message, ...);
char *to_hex(char *dest, const unsigned char *src, size_t size);
char *substring(char *dest, const char *,size_t start, size_t length);

// Don't forget to call free!!
char *my_strdup(const char *str);

// devuelve 0 si s1 contiene alguna coincidencia de s2 de lo contrario devuelve -1; len es el tamaño de s1
int strarrp(const char **s1, const char *s2, size_t len);

void die(const char *message, ...);
void *xmalloc(size_t size);
void *xrealloc(void *ptr,size_t size);
char *strremove(char*, const char *);
void clear_memory(void *buffer, size_t n);
bool begin_or_end_with_space(const char *string);
bool has_any_space(const char *string);
const char *last_modified(const char *path);
char *format_time(time_t rawtime, const char *time_format);
