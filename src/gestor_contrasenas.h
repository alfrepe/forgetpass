#pragma once

#include <stdbool.h>

#define ENV_PW_STORE "PW_STORE_DIR"
#define DEFAULT_FOLDER ".pw_store"

struct list;

int print(const char *path,const char *name);

int listar_archivos(const char *path);

int delete_file(const char *);

int show_usage(char **);

/* Compone la ruta de la carpeta pj /home/alfredo/.pw_store/
   No te olvides de llamar a free! */
char *get_store_dir(void);

// verifica que existe la carpeta '$HOME/.pw_store' si no la crea
void open_password_store(void);

// compone la ruta del registro y añade .gpg al final de la cadena pj si le pasamos gmail devolver� ->  /home/alfredo/.pw_store/gmail.gpg
char *get_entry_dir(const char *dir, const char *key);

void copy_to_clipboard(const char *text);

/*
 La contrase�a se guarda en cache durante un periodo de tiempo (por lo que he investigado parecen 10min),
 as� evitamos tener que escribirla una y otra vez, sin embargo, pensando en la seguridad esto puede ser contraproducente...
 Qu� pasar��a si nos dejamos la sesi�n abierta? cualquiera podr��a acceder a nuestras queridas y amadas contrase�as,
 ya que la clave maestra est� en la cache. Por este motivo hay que proveeer de una funci�n que cierre esa puerta.
 No he encontrado una manera de hacerlo usando las facilidades de gpgme por eso lo hago usando procesos.
*/
int reenter_passphrase(void);
const char* parse_argv(int argc, char **argv);
void free_read_files(void);
void push_file(const char *file);
int add_file_to_linked_list(const char *path,const char *name);
int decrypt_and_validate_check_pwned(const char *, const char *);
int check_pwned_one_entry(const char *pstore);
char *compose_path(const char *key);
int change_name(const char *old_name, const char *new_name);
bool will_overwritten(const char *s1, const char *s2);
bool want_overwritten(void);
int printSorted(const char *path,const char *name);
void init_buffer(size_t size);
void print_by_last_modifiest_date(const struct list*);
extern void print_file(const char *file, const char *last_modified);
int add_files_to_linked_list(const char *path);
int pseudorandom_password(char *buf, size_t buf_len, size_t password_len);
int show_read_files(const char *path);
void init_function_pointer(void) ;