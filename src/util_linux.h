#pragma once
#include <time.h>
#include <stdbool.h>
#include <stddef.h>

#define PATH_SIZE 257
#define MAX_TIME_SIZE 40

enum EXECUTE_PROGRAM_ERR {
    SUCCESS = 0,
    FORK_ERROR = 1,
    EXEC_ERROR = 2,
    WAIT_ERROR = 3,
};

// NULL si hubo un error en caso contrario éxito
const char *last_modified(const char *path);
// si time_format es NULL serÃ¡ por defecto el formato ctime();
char *format_time(time_t rawtime, const char *time_format);

// devuelve 0 si el archivo se eliminÃ³ correctamente y -1 en caso contrario.
int remove_file(const char *name);

typedef int (*callback)(const char *path,const char* file_name);

/* Si ocurre algún error se devuelve -1 en caso contrario los archivos leídos,
   si es 0 no leyó ningún archivo pero no hubo un error */
int leer_carpeta(const char *path,bool recursive,callback);

void clear_memory(void *buffer, size_t n);

// devuelve true si el directorio existe en caso contrario false
bool dir_exist(const char *dir_name);

// devuelve true si el directorio se creo correctamente en caso contrario false
bool create_dir(const char *dir_name);

// devuelve true si es un archivo corriente de lo contrario false
bool file_exist(const char *file_name);

void execute_program(char * const *argv);

time_t get_time_last_modified(const char *path);
