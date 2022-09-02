#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <limits.h>

#define CARACTER_CONTROL 27
#define NUL '\0'
#define CONTROL_C 3
#define ENTER '\n'
#define BACKSPACE 127
#define EOT 4 // EOF esta ya definido en stdio
#define URL_SIZE 43 // 37 (url length) +6 (los 5 primeros del hash +1 para el \0)
#define correct_response "yes\n"
#define wrong_response "no\n"
#define MAX_LEN_PASSWORD 101

struct MemoryStruct
{
    char *memory;
    size_t size;
};

enum PWNED_ERRORS
{
    NO_PWNED,
    PWNED,
    CONEXION_ERR,
    HASH_ERROR,
};

enum INPUT_ERRORS {
    YES_ANSWER = 1,
    NO_ANSWER,
    NO_OPERATION,
};

/**
 *  NOTE: estos valores NO PUEDEN SER NEGATIVOS!
 * Se puede utilizar cualquier valor siempre y cuando sean todos negativos
 * Me he decantado por escoger INT_MIN+1 para utilizar una constante en lugar
 * de un numero mágico elegido puramente al azar. Le sumo uno a INT_MIN para evitar usar INT_MIN
 * ya que esta constante podrÃ­a usarse en un futuro, quien sabe...
 */ 

typedef enum {
    FGETS_ERR = INT_MIN+1, // creo que seran suficientes...
    INVALID_ANSWER,
    PASSWORDS_DID_NOT_MATCH,
    EXCEEDED_LIMIT,
    INVALID_PASSWORD,
    BAD_CHARACTER,
    QUIT
} PASSWORDS_ERRORS;

size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);
// Dont't forget to call free!!!
char *download_file(const char *url);
int is_password_in_Pwned_Passwords(const char *password);
size_t get_input_from_user(char *buffer, size_t len);
int use_this_password(const char *pass);
/* si check_pwned es 1 se comprueba la contraseña en I have been pwned,
   si es 0 se omite esta comprobación. Por defecto check_pwned es 1, es decir, la contraseña se validará en HIBP */
PASSWORDS_ERRORS get_console_input(char *buf, size_t bufsize, int check_pwned);
bool invalid_passwords(const char *pass);
int get_characters_and_print_asterik(char *buf, size_t bufsize);
