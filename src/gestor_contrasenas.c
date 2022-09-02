/**
 * Primero hay que generar dos pares de claves: la p�blica y la privada, comando: gpg --gen-key
 * Nos pedir� un id de usuario y un correo electr�nico, uno de los dos se puede dejar vacio (un enter).
 * tiny password manager.
 * NO SE GARANTIZA QUE MANTENGA LA SEGURIDAD DE LAS CONTRASE�AS EN NING�N CASO! PUEDE CONTINUAR EN MEMORIA, VOLCARSE AL DISCO DURO ETC
 * https://codereview.stackexchange.com/questions/210069/a-simple-password-manager-in-c/210078#210078
*/

#include "linked_list.h"
#include "input.h"
#include "gestor_contrasenas.h"
#include "command_line.h"
#include "use_gpgme.h"
#include "util.h"
#include <assert.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <libclipboard.h>
#include <sodium.h>

#if (defined WIN32 || defined _WIN32)
    #include "util_win.h"
    #define VAR_ENVIRONMENT "USERPROFILE"
    int (*win_ptr)(const WIN32_FIND_DATA *);
    
    int add_file_to_linked_list_win(const WIN32_FIND_DATA *info) // para check-pwned en windows
    {
        if(info->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) // no queremos carpetas
            return 0;
        if(HAS_GPG_EXTENSION(info->cFileName)) {
            insert_at_end(&start,add_new_entry(info->cFileName,0));
        }
        return 1; // every call is a file
    }

    int print_in_windows(const WIN32_FIND_DATA *info)
    {
        if(info->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            return 0;
        FILETIME date = info->ftLastWriteTime;
        time_t time = FILETIME_to_time_t(date);
        char *last_modified = format_time(time,"%d/%m/%Y %H:%M:%S");
        print_file(info->cFileName,last_modified);
        return 1; // every call is a file
    }

    int print_sorted_in_windows(const WIN32_FIND_DATA *info)
    {
        if(info->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            return 0;

        time_t time = FILETIME_to_time_t(info->ftCreationTime);
        sorted_insert(&start,add_new_entry(info->cFileName,time));
        return 1; // every call is a file
    }
#else
    #define VAR_ENVIRONMENT "HOME"
    #include "util_linux.h"
#endif

int (*linux_ptr)(const char *, const char *);

int add_file_to_linked_list(const char *path, const char *name) // para check-pwned en linux
{
    if(HAS_GPG_EXTENSION(name)) {
        insert_at_end(&start,add_new_entry(name,0));
    }
    return 1; // every call is a file
}

int decrypt_and_validate_check_pwned(const char *path, const char *entry) {

    char *copy = my_strdup(entry);
    char *path_key = append_str(path,entry);
    char *password[1] = {""};
    struct data my_data;
    int ret = init_decrypt(path_key,&my_data);
    FREE_AND_NULL(path_key);
    if(ret) {
        error("'%s' couldn't be decrypted\n",strremove(copy,EXTENSION_GPG)); // no hay memoria que liberar de my_data que guay
        free(copy);
        return DECRYPT_ERROR;
    }
    free(copy);
    split_data(my_data.buf,password,ARRAY_SIZE(password));
    ret = is_password_in_Pwned_Passwords(password[0]);
    if(ret == PWNED) {
        printf("CHANGE '%s' password\n",entry);
    }
    gpgme_free_and_null(my_data.buf);
    return ret;
}

int check_pwned_one_entry(const char *pstore) {
    char *name_with_gpg_extension = append_str(check_pwned_opts.entry_name,EXTENSION_GPG);
    int ret = decrypt_and_validate_check_pwned(pstore,name_with_gpg_extension);
    free(name_with_gpg_extension);
    return ret;
}
// -------------------------------------------------------------------------
// linux
int print(const char *path,const char *name)
{
    char *fullpath = append_str(path,name);
    const char *time = last_modified(fullpath);
    print_file(name,time);
    free(fullpath);
    return 1;
}

int printSorted(const char *path,const char *name)
{
    char *fullpath = append_str(path,name);
    time_t time = get_time_last_modified(fullpath);
    sorted_insert(&start,add_new_entry(name,time));
    free(fullpath);
    return 1;
}


// -------------------------------------------------------------------------

void print_file(const char *file, const char *last_modified) {
    char *copy = my_strdup(file);
    printf("%s", strremove(copy, EXTENSION_GPG));
    free(copy);
    if(!ls_opts.only_name)
        printf(" | Modified: %s\n", last_modified ? last_modified : "error");
    else
        putchar('\n');
}

void print_by_last_modifiest_date(const struct list *entries) {
    
    while(entries != NULL) {
        char *last_modified = format_time(entries->last_modified, "%d/%m/%Y %H:%M:%S");
        print_file(entries->file,last_modified);
        entries = entries->next;
    }
}

int add_files_to_linked_list(const char *path) {
     #if _WIN32
    int read_files = leer_carpeta(path,win_ptr);
    #else
     int read_files = leer_carpeta(path,false,linux_ptr);
     #endif
     if(!read_files) {
        puts("No records! You can create new records with 'new'");
    }
    else if(read_files < 0) {
       error("No se pudieron leer los archivos\n");
    }
    return read_files;
}

void init_function_pointer(void) {
    #if _WIN32
    win_ptr = add_file_to_linked_list_win;
    #else
    linux_ptr = add_file_to_linked_list;
    #endif
}

int check_pwned(const char *pstore) {
    int ret = init_gpgme(NULL,true);
    if(ret) 
        return ret;
    if(!check_pwned_opts.check_all_entries) {
        return check_pwned_one_entry(pstore);
    }
    init_function_pointer();
    if(add_files_to_linked_list(pstore) <= 0)
        return -1;
    while(start != NULL) {
        if(decrypt_and_validate_check_pwned(pstore,start->file) == CONEXION_ERR)
            break;
        struct list *entry = next_element(&start);
        free(entry->file);
        free(entry);
    }
    return 0;
}

int listar_archivos(const char *path) {
    #if _WIN32
    win_ptr = ls_opts.sort_by_last_modified_date ? print_sorted_in_windows : print_in_windows;
    #else
    linux_ptr = ls_opts.sort_by_last_modified_date ? printSorted : print;
    #endif
    
    if(add_files_to_linked_list(path) <= 0)
        return -1;
    
    if(ls_opts.sort_by_last_modified_date) {
        print_by_last_modifiest_date(start);
        delete_list(&start);
    }
    return 0;
}

int delete_file(const char *name) {
    int exit_status = 0;
    if(HAS_GPG_EXTENSION(name)) {
        error("Don't add '%s' extension, this is done automatically by the program\n",EXTENSION_GPG);
        return -1;
    }
    char *path_to_name = compose_path(name);
    int ret = remove_file(path_to_name);
    if(ret) {
        exit_status = -1;
        error("Hubo un error, '%s' existe o es un archivo v�lido?\n",name);              
    }
    else {
        puts("Eliminado con �xito");
    }
    free(path_to_name);
    return exit_status;
}

bool will_overwritten(const char *s1, const char *s2) {
    return file_exist(s1) && file_exist(s2);
}

bool want_overwritten(void) {
    
    #define MAX_INPUT_SIZE 3
    char buffer[MAX_INPUT_SIZE] = {0};

    (void)get_input_from_user(buffer,sizeof(buffer));

    return !strcmp(buffer,"s\n") ? true : false;
}

int change_name(const char *old_name, const char *new_name) {
    char *path_to_old_name = NULL;
    char *path_to_new_name = NULL;

    int ret = -1;
    if(!strcmp(old_name,new_name)) {
        puts("Los dos nombres son iguales");
        return ret;
    }
    
    path_to_old_name = compose_path(old_name);
    if(!file_exist(path_to_old_name)) {
        error("'%s' no es un archivo v�lido o no existe\n",old_name);
        goto clear;
    }
    path_to_new_name = compose_path(new_name);
    if(will_overwritten(path_to_old_name,path_to_new_name)) {
        printf("ATENCION: '%s' ser� sobreescrito por '%s', est�s seguro? (s/n) ", new_name,old_name);
        if(!want_overwritten()) {
            puts("No se realiz� ninguna acci�n");
            goto clear;
        }
    }
    ret = rename(path_to_old_name,path_to_new_name);
    if(ret) {
        error("No se pudo renombrar el registro\n");
    }
    else
        puts("El registro se renombr� correctamente");

    clear:
    free(path_to_old_name);
    free(path_to_new_name);
    return ret;
}

char *get_store_dir(void)
{
    // build the default from HOME/DEFAULT_FOLDER
    char *env = getenv(ENV_PW_STORE);
    if(env != NULL) {
        return my_strdup(env);
    }
    const char *home = getenv(VAR_ENVIRONMENT); // PORTABLE
    if (home == NULL)
        return NULL;
    size_t len_required = strlen(home) + strlen(DEFAULT_FOLDER) + 3; // por qu� 3? 2 para las dos / del formato de snprintf y la restante para el \0
    char *def = xmalloc(len_required);
    snprintf(def, len_required, "%s/%s/", home, DEFAULT_FOLDER); // "/home/alfre/.pw_store/"
    return def;
}

void open_password_store(void)
{
    char *pstore = get_store_dir();
    if (pstore == NULL) { // no existe la variable de entorno
       error("No existe la variable de entorno %s, puede definir %s "
             "en su lugar, para establecer la ruta de la carpeta\n",VAR_ENVIRONMENT,ENV_PW_STORE);
        exit(1);
    }

    if (!dir_exist(pstore)) { // si no existe la carpeta pstore la crea // PORTABLE
        if (!create_dir(pstore)) {
            error("Error al crear la carpeta\n");
        }
    }
    free(pstore);
}

int show_usage (char **program_name)
{
  fprintf (stdout,"uso:  %s [comandos]\n\n",program_name[0]);
  fputs(
        "* Si es la primera vez que usas el programa y no has generado ninguna clave,\n"
        "haz lo siguiente: ejecuta el comando 'gpg --gen-key' para generar un nuevo\n"
        "par de claves GPG. Puedes aprender más sobre gpg aquí: https://www.genbeta.com/desarrollo/manual-de-gpg-cifra-y-envia-datos-de-forma-segura\n\n"
        "Comandos:\n"
        "  new string key string       Crea un nuevo registro\n"
        "  Opcionales con new:\n"
        "       username string        Especifica un nombre de usuario\n"
        "       website string         Especifica el sitio web\n"
        "       -nopwned               No valida la contraseña en HIBP\n"
        "       gen int                Genera una contraseña de n caracteres, donde n es int\n"
        "  update string               Actualiza un registro existente\n"
        "  Opcionales con update, por defecto cambia la contraseña:\n"
        "       username string        Especifica un nombre de usuario\n"
        "       website string         Especifica el sitio web\n"
        "       password               Pide la contraseña a través de la command line\n"
        "       -nopwned               No valida la contraseña en HIBP\n"
        "       key string             Actualiza la clave del registro\n"
        "       gen int                Genera una contraseña de n caracteres, donde n es int\n"
        "  get string                  Copia la contraseña al portapapeles\n"
        "  view string                 Muestra todos los campos del registro especificado\n"
        "  Opcionales con view:\n"
        "       -password              Muestra la contraseña\n"
        "       -username              Muestra el nombre de usuario\n"
        "       -website               Muestra el nombre del sitio web\n"
        "       -key                   Muestra la clave utilizada\n"
        "  ls                          Lista los nombres de los registros\n"
        "  Opcionales con ls:\n"
        "       last-modified          Ordena los registro según la fecha de modificación\n"
        "       only-name              Muestra solo el nombre de los registros\n"
        "  clear                       Vuelve a preguntar por la contrasea maestra\n"
        "  rm string                   Borra el registro especificado, no admite comodines\n"
        "  rename old_name new_name    Renombra un registro al nombre especificado\n"
        "  check-pwned optionalString  Verifica si alguna de las contraseas está en HIBP. Por defecto comprueba todas\n"
        , stdout);
    return 0;
}

char *get_entry_dir(const char *dir, const char *key)
{
    if(!key) BUG();
    // build the filename from DIR/KEY.gpg
    size_t size = strlen(dir) + strlen(key) + strlen(EXTENSION_GPG) + 2;
    char *path = xmalloc(size);  
    snprintf(path, size, "%s%s.gpg", dir, key);
    return path;
}

char *compose_path(const char *key) {
    char *pstore = get_store_dir();
    char *dir = get_entry_dir(pstore,key);
    free(pstore);
    return dir;
}
/*
 * clipboard_set_text_ex(...) toma un int como lenght y nosotros usamos un size_t
 * Sin embargo, como tenemos puesto un l�mite para la contrase�a de 100 caracteres
 * el tama�o del int nos llega y nos sobra.
*/
void copy_to_clipboard(const char *text) { // PORTABLE
    size_t len = strlen(text);
    clipboard_c *cb = clipboard_new(NULL);
    if (cb == NULL) {
        error("Clipboard initialization failed!\n");
        return;
    }

    if(clipboard_set_text_ex(cb, text, len, LCB_CLIPBOARD)) {
        puts("Password is now in clipboard, press enter to clear it.");
        #ifdef LIBCLIPBOARD_BUILD_X11
            /* On X11, we must stay alive until the other window has copied our data */
            fflush(stdout);
            getchar();
            goto clear;
            
        #endif
        // en windows vaciamos explicitamente el portapapeles
        getchar();
        clipboard_clear(cb,LCB_CLIPBOARD);
        clear:
        clipboard_free(cb);
        return;
    }
    error("Error: no se pudo copiar el texto al portapapeles\n");
}

int reenter_passphrase(void) // PORTABLE
{
    const char *path = path_gpgconf();
    if(path == NULL) {
        fprintf(stderr,"No se pudo obtener la ruta de gpgconf\n");
        return -1;
    }
    #ifdef WIN32
    if(!execute_program(path,"gpgconf --kill gpg-agent"))
        error("Sucedi� un error\n");
    #else
    char *argv[] = {(char *)path, "--kill","gpg-agent",NULL};
    execute_program(argv);
    #endif
    return 0;
}

/**
 * Estamos seguros de que la contrase�a no es superior a 100 caracteres, de este limite se encarga la command_line
 * no sera un numero negativo ni contendra letras p.ej "123f". Sencillamente es un numero entero.
 */
int pseudorandom_password(char *buf, size_t buf_len, size_t password_len) {
    assert(buf_len > password_len); // actualmente tiene un limite de 100
      const char *chars = {
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "1234567890"
        "!@#$%^&*()"
        "`~-_=+[{]{\\|;:'\",<.>/? "};
    if(sodium_init() < 0) {
        error("Libsodium initialization failed!\n");
        return -1;
    }
    size_t chars_len = strlen(chars)-1;
    for(size_t i = 0; i < password_len; ++i) {
        buf[i] = chars[randombytes_uniform(chars_len)];
    }
    return 1; // no error

}
