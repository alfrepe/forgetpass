#include "input.h"
#include "util.h"
#include "getch.h"

#if _WIN32
    #include "util_win.h"
#else
    #include <openssl/sha.h>
#endif

#ifndef SHA_DIGEST_LENGTH
    #define SHA_DIGEST_LENGTH 20
#endif
#if (defined WIN32 || defined _WIN32)
    #define SHA1(x,y,z) SHA1(x,y)
#endif

#include <assert.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <ctype.h>

#define CORRECT_RESPONSE 200 // 200 OK

size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = xrealloc(mem->memory, mem->size + realsize + 1);
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

char *download_file(const char *url)
{
    CURL *curl_handle;
    CURLcode res;
    long response_code = 0;
    struct MemoryStruct chunk;

    chunk.memory = xmalloc(1); /* will be grown as needed by the realloc above */
    chunk.size = 0;           /* no data at this point */

    /* init the curl session */
    curl_handle = curl_easy_init();
    if (curl_handle == NULL)
    {
        BUG();
        return NULL;
    }

    /* specify URL to get */
    curl_easy_setopt(curl_handle, CURLOPT_URL, url);

    /* send all data to this function  */
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);

    res = curl_easy_perform(curl_handle);
    // res = CURLE_AGAIN; // provocar error

    if (res != CURLE_OK) // pj si no hay internet
    {
        fprintf(stderr, "Error: %s\n",
                curl_easy_strerror(res));
        FREE_AND_NULL(chunk.memory);
        goto cleanup;
    }
    
    curl_easy_getinfo(curl_handle,CURLINFO_RESPONSE_CODE,&response_code);
    if(response_code != CORRECT_RESPONSE) {
        fprintf(stderr,"Error: http response code %ld\n",response_code);
        FREE_AND_NULL(chunk.memory);
    }
       
    cleanup:
        curl_easy_cleanup(curl_handle);
        curl_global_cleanup();

    return chunk.memory;
}

int is_password_in_Pwned_Passwords(const char *password) {
    int pwned = NO_PWNED;
    char dest[SHA_DIGEST_LENGTH*2+1] = {0};
    char sha1_hex_copy[SHA_DIGEST_LENGTH*2+1] = {0};

    unsigned char *sha1 = SHA1((unsigned char *)password,strlen(password),NULL); // no thread safe
    // assert(sha1);
    if(sha1 == NULL) {
        return HASH_ERROR;
    }

    char *sha1_hex = to_hex(dest,sha1,SHA_DIGEST_LENGTH);
    strcpy(sha1_hex_copy,sha1_hex);
    char *prefix = sha1_hex+5; // 5 primeros d�gitos del hash
    char *sufix = 5+strlen(sha1_hex_copy); // los d�gitos restantes

    char url[URL_SIZE] = "https://api.pwnedpasswords.com/range/";
    strcat(url,50);

    char *lines = download_file(url);
    if(lines == NULL) {
        return CONEXION_ERR; // no hay internet o algo parecido
    }
    char *token = strtok(lines,":\n");    
    while(token != NULL) {
        if(strcmp(token,sufix) == 0) {
            pwned = PWNED;
            break;
        }
        token = strtok(NULL,":\n");
        token = strtok(NULL,":\n");
    }
    free(lines);
    return pwned;
}

size_t get_input_from_user(char *buffer, size_t len) {

    if(fgets(buffer,len,stdin) != NULL) {
        return strlen(buffer);
    }
    return 0;
}

// very improbably passwords TODO: quitar esta restricci�n?
bool invalid_passwords(const char *pass) {
    size_t size = strlen(pass);
    if(size == 0) {  // que la contrase�a no sea un enter o un control+espacio (NUL)
        error("La contrase�a est� vacia\n");
        return true;
    }
    if(isspace((unsigned char)*pass) || isspace((unsigned char)pass[size-1])) {
        error("No puede empezar ni terminar con un espacio en blanco\n");
        return true;
    }
    return false;
}

// https://haveibeenpwned.com/Passwords el espacio es un caracter v�lido, curioso... Sin embargo, el enter no es v�lido
int use_this_password(const char *pass) {
    char response_from_user[5] = {0}; // por qu� 5? pues porque si no cosas como 'yess' ser�an v�lidas
    int res = is_password_in_Pwned_Passwords(pass);
    if(res == PWNED) {
        printf("%s","Esta contrase�a NO deberia ser usada, se encuentra en Pwned Passwords!\n"
              "Quieres usar esta contrase�a igualmente? (yes/no): ");
        size_t input_len = get_input_from_user(response_from_user,sizeof(response_from_user));
        if(input_len == 0) { // control+d o algo por el estilo
            return FGETS_ERR;
        }
        else if(input_len == strlen(correct_response) && !strcmp(response_from_user,correct_response)) { // "yes" // TODO: hacer una funci�n
            return YES_ANSWER; 
        }
        else if(input_len == strlen(wrong_response) && !strcmp(response_from_user,wrong_response)) { // "no"
            return NO_ANSWER; 
        }
        // por lo visto no sabe leer, no introdujo "yes" o "no"
        return INVALID_ANSWER; 
    }
    else if(res != NO_PWNED) { // si no est� pwned
        if(res == HASH_ERROR)
            error("No se pudo obtener el hash SHA1, ");
        puts("NO se validar� la contrase�a en I Have Been Pwned!");
        return NO_OPERATION;
    }
    return NO_PWNED; // no est� presente en pwned passwords
}

int get_characters_and_print_asterik(char *buf, size_t bufsize) { // TODO: pensar otra manera de hacerlo en windows, no puedo soportar tantos case
    assert(bufsize > 0);
    bool stop = false;
    char ch = ' ';
    for (size_t i = 0; i < bufsize && !stop ;)
    {
        switch(ch = getch ()) { // NOTA: caracteres no ascii como la � aparecer�n como dos ** en lugar de 1
            case CARACTER_CONTROL: // f1,f2,esc,supr,insert, flechas de direcci�n etc etc
            case EOT: // ctrl+d en linux o ctrl+z en windows
            case NUL: // tipicamente control+espacio
                putchar('\n');
                return BAD_CHARACTER;
            case CONTROL_C:
                return QUIT;
            case ENTER:
            case '\r':
                putchar('\n');
                buf[i] = '\0';
                stop = true;
                break;            
            case BACKSPACE:
            case '\b':
                if(i > 0) {
                    i--;
                    printf("\b \b");
                }
                break;
            default:
                buf[i++] = ch;
                putchar('*');
        }
        if(i == bufsize) { // se super� el l�mite de caracteres para la contrase�a
            putchar('\n');
            return EXCEEDED_LIMIT;
        }
    }
    return 0;
}

PASSWORDS_ERRORS get_console_input(char *buf, size_t bufsize, int check_pwned)
{
    char *buf_match = NULL;
    char *buf2 = NULL;
    unsigned intentos = 0;
    do {
        if(intentos == 0)
            printf("Insert new password (ctrl+c to abort): ");
        else {
            buf_match = buf;
            printf("Repeat your password: ");
        }
        int ret = get_characters_and_print_asterik(buf,bufsize);
        if(ret == BAD_CHARACTER || ret == EXCEEDED_LIMIT || ret == QUIT) { // we can't continue
            FREE_AND_NULL(buf2);
            return ret;
        }
        // repetimos la contrase�a
        if(!buf2)
            buf2 = my_strdup(buf);
        // si las contrase�as coinciden procedemos a comprobar si se encuentra pwned
        if(buf_match != NULL && !strcmp(buf_match,buf2)) {
            if(invalid_passwords(buf2)) {  // que la contrase�a no sea un enter o un control+espacio (NUL)
                FREE_AND_NULL(buf2);
                return INVALID_PASSWORD;
            }
            if(!check_pwned) { // no queremos comprobar la contrase�a en HIBP (comando -nopwned)
                break;
            }
            // miramos si esta en HIBP y si quiere usarla
            int resp = use_this_password(buf2);
            if(resp == NO_PWNED || resp == YES_ANSWER || resp == NO_OPERATION) // la contrase�a no esta pwned, queremos usar la contrase�a a pesar de estar pwned o sucedi� alg�n error
                break;
            else if(resp == FGETS_ERR || resp == INVALID_ANSWER) {
                FREE_AND_NULL(buf2);
                return resp;
            }
            // NO_ANSWER
            buf_match = NULL;
            intentos = 0;
            FREE_AND_NULL(buf2);
            intentos -= 1;
        }
        ++intentos;
    }while(intentos != 2);

    FREE_AND_NULL(buf2);

    return intentos == 1 ? strlen(buf) : PASSWORDS_DID_NOT_MATCH;
}
