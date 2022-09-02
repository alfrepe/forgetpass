#include "command_line.h"
#include "use_gpgme.h"
#include "gestor_contrasenas.h"
#include "util_linux.h"
#include "input.h"
#include "util.h"
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <sodium.h>

#define USERNAME new_opts.sub_commands[0].command_parameter
#define WEBSITE new_opts.sub_commands[1].command_parameter
#define GEN_PASSWORD_IS_NOT_SET new_opts.password_len == -1
#define MAX_ENTRIES 4

struct crypto_ctx{
    gpgme_ctx_t ctx;
    gpgme_key_t keylist[2];
    gpgme_data_t data[2];
    gpgme_error_t err_gpgme;

} cc;

const char *path_gpgconf()
{
    gpgme_engine_info_t info;

    gpgme_get_engine_info(&info);
    while (info)
    {
        if (info->protocol == GPGME_PROTOCOL_GPGCONF)
            return info->file_name;
        info = info->next;
    }
    return NULL;
}

int init_gpgme(const char *name, bool decrypt) {
    size_t n_keys = 0;
    gpgme_error_t err = init_crypto(name,&n_keys,decrypt);
    if (!n_keys) {
        error("La clave '%s' no existe!\n",name);
        return KEY_NOT_EXIST;
    }
    if(err) {
        error("Error: %s\n",gpgme_strerror (err));
        return CRYPTO_ERROR;
    }
    return 0;
}

void pretty_print_keys(const gpgme_key_t key) {
    if(!key) {
        error("No se puede mostrar información acerca de la clave\n");
        return;
    }

    printf("name: [%s] | ", key->uids->name);
    printf("email: [%s] | ", key->uids->email);
    printf("keyid: [%s] | ", key->subkeys->keyid);
    char *time =  ctime((const time_t *const)&key->subkeys->timestamp);
    delete_newline(time);
    printf("fecha: %s | ", time);
    printf("caduca: %s", ctime((const time_t *const)&key->subkeys->expires));
   
}

gpgme_error_t init_crypto(const char *key_name, size_t *n_keys, bool decrypt)
{
    setlocale(LC_ALL, "");
    gpgme_check_version(NULL);
    gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));
    #ifdef LC_MESSAGES // compatibilidad con windows
        gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
    #endif
    *n_keys = decrypt ? 1 : 0; // n_keys solo sirve para encrypt y nos dice si la clave existe o no
    gpgme_error_t err = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
    if (err)
        return err;

    err = gpgme_new(&cc.ctx);
    if (!err && !decrypt)
    {
        err = gpgme_op_keylist_start(cc.ctx, key_name, 0);
        if (!err)
        {
            err = gpgme_op_keylist_next(cc.ctx, &cc.keylist[0]);
            
            if (!err) {
                ++(*n_keys);
                new_opts.keyname = cc.keylist[0] ? cc.keylist[0]->uids->uid : " ";
                err = gpgme_op_keylist_end(cc.ctx);
            }
        }
    }
    return err;
}

void release_data() {
    gpgme_data_release(cc.data[0]);
}

gpgme_error_t decrypt_from_file(const char *path)
{
    gpgme_error_t err = gpgme_data_new_from_file(&cc.data[0], path, 1);
    if (err)
        return err;

    err = gpgme_data_new(&cc.data[1]);
    if(err) {
        return err;
    }
    // NOTA: no estoy seguro de la portabilidad de estos codigos error...
    // si se cancela la operacion err = 83886179
    // si se introduce mal la contraseÃ±a en los 3 intentos, err = 67108875
    return gpgme_op_decrypt(cc.ctx, cc.data[0], cc.data[1]);
}

char *decrypt(const char *path, size_t *len) {
    release_data();
    gpgme_err_code_t err = decrypt_from_file(path);
    if(err) {
        //error("Error: %s\n",gpgme_strerror (err));
        return NULL;
    }
    return gpgme_data_release_and_get_mem(cc.data[1], len);
}

void split_data(char *string, char **data, size_t data_size) {

    data[0] = strtok(string,"\n"); // contraseña
    for(size_t i = 1; i < data_size; i++)
        data[i] = strtok(NULL,"\n"); 
}

bool data_is_malformed(const char *s, size_t len) {
    if(!len || s[len-1] != '\0')
        return true;
    return false;
}

// forma una sola lí­nea en my_data.buf con la contraseña, username y website separados por '\n'
struct data compose_data(ENTRY *entry) {
    struct data my_data;
    size_t password_len = strlen(entry->pass);
    if(!password_len) {
        // deberíamos entrar solo cuando estamos en "update"
        strcpy(entry->pass, " ");
        password_len = 1; // el espacio " " ocupa 1byte
    }
   
    // TODO: me podrí­a ahorrar estos dos strlen cuando estoy en "new", pero cómo?!
    size_t len_username = strlen(entry->username);
    size_t len_website = strlen(entry->website);
    size_t keylen = strlen(entry->key);
    size_t total = password_len+len_username+len_website+keylen+4; // 3 para los '\n' que hay en la cadena de formato del snpritnf y 1 para el \0

    my_data.buf = xmalloc(total);
    my_data.size = total;

    int read = snprintf(my_data.buf,total,"%s\n%s\n%s\n%s",entry->pass,entry->username,entry->website,entry->key);
    clear_memory(entry->pass,password_len);
    if(read >= total) {
        FREE_AND_NULL(my_data.buf);
        //error("Error: attempt to snprintf into too-small buffer\n");
        BUG();
    }
    return my_data;
}
struct data diff_data(char *new_data, char *old_data) { // TODO: tendrí­a que ser const

    char *new_str[MAX_ENTRIES] = {NULL};
    char *old_str[MAX_ENTRIES] = {NULL};
    split_data(new_data,new_str,ARRAY_SIZE(new_str));
    split_data(old_data,old_str,ARRAY_SIZE(old_str));
    for(int i = 0; i < MAX_ENTRIES; ++i) {
        if(strcmp(new_str[i]," ")) {
            old_str[i] = new_str[i];
        }
    }
    ENTRY entry = { .pass = old_str[0], .username = old_str[1], .website = old_str[2], .key = old_str[3] };
    return compose_data(&entry);
}

struct data get_updated_data(ENTRY *entry, char *old_data) {
    struct data new_data = compose_data(entry);
    struct data updated_data = diff_data(new_data.buf,old_data);
    gpgme_free_and_null(old_data);
    FREE_AND_NULL(new_data.buf);

    return updated_data;
}

int ask_for_password(char *buf, size_t buf_len, bool get_password_from_cli) {
    if(get_password_from_cli) {
        return get_password(buf, buf_len); // pedimos la contraseña a traves de la cli
    }
    return pseudorandom_password(buf,buf_len,new_opts.password_len);   
}

RETURN_TYPE update_entry(const char *keyfile)
{
    puts("Updating exist key...");
    char pass_buffer[MAX_LEN_PASSWORD] = {0}; // la contraseña
    size_t len_old_data = 0;
    if(update_opts.update_password) {
        if(ask_for_password(pass_buffer,sizeof(pass_buffer),GEN_PASSWORD_IS_NOT_SET) <= 0) {
            return EXIT_FAILURE;
        }
    }
    char *old_data = decrypt(keyfile,&len_old_data);
    int ret = validate_decrypt(old_data,len_old_data);
    if(ret == DECRYPT_ERROR) { // operación cancelada o no es un archivo gpg válido
        error("No se pudo desencriptar\n");
        return ret; 
    }
    else if(ret == MALFORMED_DATA) {
        error("Error: el formato del archivo no es válido\n");
        return ret;
    }
    ENTRY entry = { .pass = pass_buffer, .username = USERNAME, .website = WEBSITE, .key = new_opts.keyname };
    struct data updated_data = get_updated_data(&entry,old_data);
    
    release_data();
    if (init_encrypt(keyfile, &updated_data))
        return EXIT_FAILURE;
    puts("La información se actualizó correctamente");

    return 0;
}

int new_entry(const char *keyfile) {
    char pass_buffer[MAX_LEN_PASSWORD] = {0};
    puts("Inserting new key...");
    if(ask_for_password(pass_buffer,sizeof(pass_buffer),GEN_PASSWORD_IS_NOT_SET) <= 0)
        return -1;
    ENTRY entry = { .pass = pass_buffer, .username = USERNAME, .website = WEBSITE, .key = new_opts.keyname }; 
    struct data my_data = compose_data(&entry);
    if (init_encrypt(keyfile, &my_data))
        return -1;
    puts("Contraseña insertada con éxito!");
    
    return 0;
}

void print_info_key() {
    if(cc.keylist[0]) {
        printf("Se va a utilizar la clave: [%s], email: [%s], keyid: [%s]\n",
                cc.keylist[0]->uids->name, cc.keylist[0]->uids->email, cc.keylist[0]->subkeys->keyid);
    }
}

RETURN_TYPE insert_entry(const char *pstore, const char *file,bool update)
{
    int ret = init_gpgme(new_opts.sub_commands[2].command_parameter,false);
    if(ret)
        return ret;
    char *keyfile = get_entry_dir(pstore, file); // si es NULL significa que malloc falló, pero dado que utilizamos un wrapper esto no deberí­a pasar
    bool fileExist = file_exist(keyfile);
    if (!update && fileExist) {
          error("'%s' ya existe, si quieres actualizarlo usa 'update'\n",file);
          goto cleanup;
    }
    else if(update && !fileExist) { // queremos actualizar un registro pero no existe
        error("'%s' no existe, si quieres crearlo usa 'new'\n",file);
        goto cleanup;
    }
    print_info_key();
    if(update) 
        ret = update_entry(keyfile);
    else
        ret = new_entry(keyfile);
    cleanup:
    free(keyfile);
    return ret;
}

RETURN_TYPE validate_decrypt(char *str, size_t len) {
    if (str == NULL) {
        return DECRYPT_ERROR;
    }
    if(data_is_malformed(str,len)) {
        gpgme_free_and_null(str);
        return MALFORMED_DATA;
    }
    return 0;
}

int init_decrypt(const char *path,struct data *data) {
    size_t len = 0;
    if (!file_exist(path)) {
        return KEY_NOT_EXIST;
    }
    data->buf = decrypt(path,&len);
    data->size = len;
    return validate_decrypt(data->buf, data->size);
}

RETURN_TYPE get_entry(const char *pstore, const char *file, bool plaint_text)
{
    int ret = init_gpgme(NULL,true);
    if(ret)
        return ret;
    char *t[MAX_ENTRIES] = {NULL};
    struct data my_data;
    char *keyfile = get_entry_dir(pstore, file); // si es NULL significa que malloc falló, pero dado que utilizamos un wrapper esto no debería pasar
    ret = init_decrypt(keyfile,&my_data);
    FREE_AND_NULL(keyfile);
    if(ret == DECRYPT_ERROR) {
        error("No se pudo desencriptar\n");
        return ret;
    }
    else if(ret == MALFORMED_DATA) {
        error("Error: el formato del archivo no es válido\n\n"); // el archivo puede ser válido, pero no ha sido creado desde nuestro programa porque carece del '\0'
        return ret;
    }
    else if(ret == KEY_NOT_EXIST) {
        error("Error: El registro proporcionado no existe\n");
        return ret;
    }
    split_data(my_data.buf,t,ARRAY_SIZE(t));

    if(plaint_text) {
        // mostrarlos en el orden especificado a través de la cli
        for(size_t i = 0; i < 4; i++) {
            if(view_opts.view_password == i)
                printf("Password: %s\n", t[0]);
            if(view_opts.view_username == i)
                printf("Username: %s\n", t[1]);
            if(view_opts.view_website == i)
                printf("Website: %s\n", t[2]);
            if(view_opts.view_key == i) {
                printf("key: %s\n", t[3]);
            }
        }
    }
    else 
        copy_to_clipboard(my_data.buf);

    gpgme_free_and_null(my_data.buf);
    return 0;
}

int write_data(const char *path) {

    size_t enc_len = 0;
    int ret = 0;
    FILE *fd = fopen(path, "wb");
    if (fd == NULL) {
        error("Error: no se pudo crear el archivo '%s'\n",path);
        release_data();
        return -1;
    }

    char *enc = gpgme_data_release_and_get_mem(cc.data[1], &enc_len); // TODO: verificar contra NULL
    if(!enc) {
        error("No se pudo encriptar\n");
        fclose(fd);
        return -1;
    }
    if(fwrite(enc, sizeof(*enc), enc_len, fd) != enc_len) {
        error("Error: No se pudo escribir en el archivo '%s'\n",enc);
        ret = -1;
    }
    release_data();
    gpgme_free(enc);
    fclose(fd);

    return ret;
}

int init_encrypt(const char *path, struct data *my_data) {

    gpgme_error_t err = encrypt_to_file(path,my_data);
    if(err) {
        error("Error: %s\n",gpgme_strerror (err));
        return -1;
    }
    return write_data(path);
}

gpgme_error_t encrypt_to_file(const char *path, struct data *my_data)
{    
    gpgme_error_t err = gpgme_data_new_from_mem(&cc.data[0], my_data->buf, my_data->size, 1);
    FREE_AND_NULL(my_data->buf);
    if(err) 
        return err;
    err = gpgme_data_new(&cc.data[1]);
    if(err) 
        return err;  
    err = gpgme_op_encrypt(cc.ctx, &cc.keylist[0], GPGME_ENCRYPT_ALWAYS_TRUST,cc.data[0], cc.data[1]);
    if (err)
        release_data();
    return err;
}
// > 0 exito
int get_password(char *pass_buffer, size_t size_pass_buffer) {

    int input_len = get_console_input(pass_buffer, size_pass_buffer,new_opts.check_pwned);
    if (input_len == BAD_CHARACTER)
        error("Caracter no admitido\n");
    else if (input_len == FGETS_ERR) 
        error("No se pudieron leer los datos\n");
    else if (input_len == EXCEEDED_LIMIT) 
        error("Maximo de caracteres permitidos %d\n", size_pass_buffer);
    else if (input_len == PASSWORDS_DID_NOT_MATCH) 
        error("Passwords didn't match\n");
    else if(input_len == INVALID_ANSWER) 
        error("Respuesta incorrecta, se esperaba yes/no\n");

    return input_len;           
}

void cleanup_crypto(void)
{
    if(cc.keylist[0])
        gpgme_key_unref(cc.keylist[0]); // equivalente a gpgme_key_release
    gpgme_release(cc.ctx);
}
