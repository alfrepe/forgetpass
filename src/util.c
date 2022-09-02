#include "util.h"

#if (_WIN32)
    #include "util_win.h"
#else
    #include "util_linux.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <limits.h>
#include <time.h>

#define LEN(str) str ? strlen(str) : 0

// set buffer to 0 in range n; NOTA: memset puede ser optimizado y eliminado por el compilador.
void clear_memory(void *buffer, size_t n) {
    volatile unsigned char *p = buffer;
    while(n--) {
        *p++ = 0;
    }
}

int is_all_space(const char *str) {
    if(str == NULL || !isspace((unsigned char)*str)) { // la precondicion de isspace evita que char *ptr = ""; sea considerado como un espacio
        return 0;
    }
    while(*str) {
        if(!isspace((unsigned char)*str++)) {
            return 0;
        }
    }
    return 1;
}

char *delete_newline(char *str) {
    char *ptr = NULL;
    if(str) {
        ptr = strchr(str,'\n');
        if(ptr) {
            *ptr = '\0';
        }
    }
    return str;
}

int strarrp(const char **s1, const char *s2, size_t len) {

    for(size_t i = 0; i < len; ++i) {
        if(strcmp(s1[i],s2) == 0) {
            return 0;
        }
    }
    return -1;
}

char *append_str(const char *s1, const char *s2) {
    size_t total_len = strlen(s1)+strlen(s2)+1;
    char *fullpath = xmalloc(total_len); // tiene que terminar en \0
    snprintf(fullpath,total_len,"%s%s",s1,s2);
    return fullpath;
}

char *to_hex(char *dest, const unsigned char *src, size_t size) {
    for(size_t i = 0; i < size; i++) {
         snprintf(&dest[i*2],size, "%02X", src[i]);
    }
    return dest;
}

char *substring(char *dest, const char *src, size_t start, size_t length) {
  size_t source_len = strlen(src);
  if (start > source_len) start = source_len;
  if (start + length > source_len) length = source_len - start;
  memmove(dest, &src[start], length);
  dest[length] = 0;
  return dest;
}

// TODO: y si strdup est� disponible?
char *my_strdup(const char *str) {
    if(str == NULL) return (char *)str;
    char *s = xmalloc(strlen(str)+1);
    return strcpy(s,str);
}

void die(const char *message, ...) {
    va_list arg;
    va_start (arg,message);
    vfprintf(stderr,message,arg);
    va_end (arg);
    fprintf(stderr,"\n");
    exit(EXIT_FAILURE);
}

void REPORT_BUG_AND_ABORT(const char *file, int line) {
    fprintf(stderr,"Oops... Probablemente esto sea un BUG.\n"
                   "Ocurri� en: '%s:%d'\n",
                    file,line );
    abort();
}

bool has_any_space(const char *string) {
    if(!string) return false;

    return strchr(string,' ') ? true : false;
}

bool begin_or_end_with_space(const char *string) {

    size_t size = LEN(string);
    if(!string || !size) return false;

    return isspace((unsigned char)*string) || isspace((unsigned char)string[size-1]);

}

char *strremove(char *str, const char *sub) {
    if(sub == NULL) {
        return NULL;
    }
    size_t len = strlen(sub);
    char *p = str;
    while ((p = strstr(p, sub)) != NULL) {
        memmove(p, p + len, strlen(p + len) + 1);
    }

    return str;
}

void error(const char *message, ...) {
    va_list arg;
    va_start (arg,message);
    vfprintf(stderr,message,arg);
    va_end (arg);
}

void *xmalloc(size_t size) {

    void *p = malloc(size);
    if(!p) {
        die("Out of memory, malloc failed (tried to allocate %lu bytes)",
			size);
    }
    return p;
}

void *xrealloc(void *ptr,size_t size) {
    void *p = realloc(ptr,size);
    if(!p) {
        die("Out of memory, realloc failed (tried to allocate %lu bytes)",
			size);
    }
    return p;
}

// time functions
const char *last_modified(const char *path)
{
    time_t rawtime = get_time_last_modified(path);
    if (rawtime)
        return format_time(rawtime, "%d/%m/%Y %H:%M:%S");
    return NULL;
}

char *format_time(time_t rawtime, const char *time_format)
{
    static char buffer_time[MAX_TIME_SIZE] = {0};
    struct tm *timeinfo = localtime(&rawtime);
    if(!timeinfo)  // si le pasamos p.ej rawtime 99999999999999999
       return NULL;
    if (time_format == NULL)
        return delete_newline(ctime(&rawtime)); // ctime a�ade un salto de l�nea, yo no lo quiero

    if (!strftime(buffer_time, sizeof(buffer_time), time_format, timeinfo))
    {
        //error("No es posible mostrar la fecha, es demasiado larga");
        return NULL;
    }
    return buffer_time;
}
