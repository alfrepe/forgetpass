#pragma once

#include <gpgme.h>
#define QUOTE '\''

typedef struct {
    char *pass;
    const char *username;
    const char *website;
    const char *key;
}ENTRY;

typedef enum {
    KEY_NOT_EXIST = 1,
    CRYPTO_ERROR,
    DECRYPT_ERROR,
    MALFORMED_DATA

} RETURN_TYPE;

struct data {
    size_t size;
    char *buf;
};

#define gpgme_free_and_null(str) \
    do                   \
    {   if(str)                 \
            gpgme_free(str);         \
        (str) = NULL;      \
    } while (0 != 0)


// https://github.com/gpg/gpa/blob/master/src/gpgmetools.c#L501
const char *path_gpgconf();

int init_gpgme(const char *, bool);

/*
 configuraciones iniciales:
 https://www.gnupg.org/documentation/manuals/gpgme/Library-Version-Check.html#Library-Version-Check
*/
gpgme_error_t init_crypto(const char *key_name, size_t *n_keys, bool all_keys);

gpgme_error_t decrypt_from_file(const char *path);
char *decrypt(const char *path, size_t *);

/*
* 0 en caso de �xito, -1 en caso de error
* path -> la ruta donde va a escribir el archivo .gpg que contendra la contrase�a
* buf -> la contrase�a
* len -> longitud de la contrase�a
*/
gpgme_error_t encrypt_to_file(const char *path, struct data *my_data);
void cleanup_crypto(void);
RETURN_TYPE insert_entry(const char *keyfile, const char *file, bool update);
RETURN_TYPE get_entry(const char *keyfile, const char *file, bool plaint_text);
void release_data(void);
const char *path_gpgconf(void);
void pretty_print_keys(const gpgme_key_t);
void split_data(char *string, char **data, size_t data_size);
int get_password(char *pass_buffer, size_t size_pass_buffer);
struct data compose_data(ENTRY*);
struct data diff_data(char *new_data, char *old_data);
RETURN_TYPE update_entry(const char *keyfile);
int new_entry(const char *keyfile);
bool data_is_malformed(const char *s, size_t len);
int write_data(const char *path);
int init_encrypt(const char *path, struct data *my_data);
int check_pwned(const char *keyfile);
RETURN_TYPE validate_decrypt(char *s, size_t len);
int init_decrypt(const char *,struct data *data);
struct data get_updated_data(ENTRY *entry, char *old_data);
void print_info_key(void);
int ask_for_password(char *buf, size_t buf_len, bool get_password_from_cli);