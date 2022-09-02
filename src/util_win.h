#pragma once
#include <Windows.h> 
#include <bcrypt.h>     // Cryptography API
#include <stdbool.h>

/*
#pragma comment(lib,"bcrypt.lib")
#pragma comment(lib,"Ws2_32.lib")
#pragma comment(lib,"Crypt32.lib")
#pragma comment(lib,"Wldap32.lib")
#pragma comment(lib, "Normaliz.lib")
#pragma comment(lib, "Advapi32.lib")
*/
typedef struct {
	BCRYPT_ALG_HANDLE m_alg;
	BCRYPT_HASH_HANDLE m_hash;
	NTSTATUS error;
} crypto_handles;

typedef int (*callback)(const WIN32_FIND_DATA *);

void InitializeCryptHashObjects(crypto_handles * hand_crypto);
void ClearCryptHashObjects(const crypto_handles *hand_crypto);
unsigned char *Sha1Hash(const char *data, size_t length, const crypto_handles *hand_crypto);
unsigned char *SHA1(const char* text,size_t len);
BOOL execute_program(const char *path, LPSTR cmdLine);
/**
 * FAIL 0
 * SUCCESS != 0
 * Para mantener la compatibilidad con la api de linux niego el valor de retorno
*/
int remove_file(const char *name);
bool dir_exist(const char *dir_name);
/**
 * FAIL  0
 * SUCCESS OTHERWISE
 */
bool create_dir(const char *dir_name);
bool file_exist(const char *file_name);
int leer_carpeta(const char *path, callback ptr);
time_t get_time_last_modified(const char *path);
time_t FILETIME_to_time_t (FILETIME file_t);
int save_files_win(const WIN32_FIND_DATA *info);
int print_in_windows(const WIN32_FIND_DATA *info);
int print_sorted_in_windows(const WIN32_FIND_DATA *info);