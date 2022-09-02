/**
 * si chrome esta abierto sqlite3_exec fallará, la solución a este problema es copiar la db, leerla y luego borrarla
 * la contraseña es 'peanuts' si no hay disponible un gestor de contraseñas
 * copiar la db a mi directorio y luego borrarla
 */
#include <libsecret-1/libsecret/secret.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <assert.h>

const SecretSchema *
get_chrome_like_schema (void)
{
    static const SecretSchema the_schema = {
        "chrome_libsecret_os_crypt_password_v2",
		SECRET_SCHEMA_NONE,
        {
            { "application", SECRET_SCHEMA_ATTRIBUTE_STRING },
			{ NULL, 0 },
        }
    };
    return &the_schema;
}

static int Error(const char *message) {
	fprintf(stderr,"Error: %s\n",message);
	return -1;
}

static char *get_chrome_safe_storage_password(const char *browser) {

	GError *error = NULL;
	gchar *password = secret_password_lookup_sync(get_chrome_like_schema(), NULL, &error, "application", browser, NULL); // no olvidarse de secret_password_free()
	if(error) {
		g_error_free(error);
		return NULL;
	}
	return password;
}

bool copy_file_in_chunks(const char *from, const char *to)
{
	unsigned char chunk[8192] = {0};
	size_t len;
	FILE *fd_from = fopen(from,"r");
	if(!fd_from) {
		return false;
	}
	FILE *fd_to = fopen(to,"w");
	if(!fd_to) {
		fclose(fd_from);
		return false;
	}
	
	while ((len = fread(chunk, 1, sizeof(chunk), fd_from)) > 0) {
    	fwrite(chunk, 1, len, fd_to);
  	}
	fclose(fd_from);
	fclose(fd_to);
	
	return true;
}

off_t get_file_size(FILE *fd) {
	if(fd) {
		struct stat stbuf;
		if((fstat(fileno(fd),&stbuf) != 0) || (!S_ISREG(stbuf.st_mode)))
			return -1;
		return stbuf.st_size;
	}
	return -1;

}
// fuck off SEEK_END portability issues, http://www.cplusplus.com/reference/cstdio/fseek/
bool copy_file(const char *from, const char *to) {
	bool ret = false;
	unsigned char *buf = NULL;
	FILE *fd_from = fopen(from,"r");
	if(!fd_from)
		return false;
	off_t file_size;
	if((file_size = get_file_size(fd_from)) < 0) {
		fclose(fd_from);
		return false;
	}
	//printf("%lu\n",file_size);
	FILE *fd_to = fopen(to,"w");
	if(!fd_to) {
		fclose(fd_from);
		return false;
	}
	buf = malloc(file_size*sizeof(*buf));
	if(fread(buf,1,file_size,fd_from) != file_size) {
		goto clear;
	}
	if(fwrite(buf,1,file_size,fd_to) != file_size) {
		goto clear;
	}
	ret = true;
	clear:
	free(buf);
	fclose(fd_to);
	fclose(fd_from);
	return ret;
}

int get_pkcs5_pbkdf2_hmac(const char *pass, unsigned char *output, size_t outputlen) {
	
	char *salt = "saltysalt";
	size_t salt_len = strlen(salt);
	int ret = PKCS5_PBKDF2_HMAC(pass, -1, (unsigned char *)salt, salt_len, 1, // si el segundo parametro de PKCS5_PBKDF2_HMAC es -1 se calcula la longitud de pass usando strlen
								EVP_sha1(),outputlen,output);
	return ret;
}

int get_cipher(unsigned char *buffer, size_t bufferlen, const char *browser) {
	const char *default_pass = "peanuts"; // in some distributions that not have installed password manager like seahorse this is the default password
	char *pass = get_chrome_safe_storage_password(browser);
	if(!get_pkcs5_pbkdf2_hmac(pass ? pass : default_pass ,buffer,bufferlen))
		return Error("get_pkcs5_pbkdf2_hmac()");
	secret_password_free(pass);
	return 0;
}

int aes_decrypt(char **plaintext_password, const unsigned char *key, const unsigned char *cipher_password, size_t cipher_passwordlen) {
	int len;
	int plaintext_password_len;
	EVP_CIPHER_CTX *ctx = NULL;
	char *iv = "                ";
	*plaintext_password = malloc(cipher_passwordlen);
	if(!(ctx = EVP_CIPHER_CTX_new())) { // fputs("EVP_CIPHER_CTX_new() failure",stderr);
		return Error("EVP_CIPHER_CTX_new failure");
	}
	// key es get_chrome_safe_storage_password()
	if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, (unsigned char *)iv)) {
		EVP_CIPHER_CTX_free(ctx);
		return Error("EVP_DecryptInit_ex() failure");

	}
	if(!EVP_DecryptUpdate(ctx, (unsigned char *)*plaintext_password, &len, cipher_password, cipher_passwordlen)) {
		EVP_CIPHER_CTX_free(ctx);
		return Error("EVP_DecryptUpdate() failure");
	}
	plaintext_password_len = len;

	if(!EVP_DecryptFinal_ex(ctx, (unsigned char *)(*plaintext_password)+len, &len)) { // en contraseñas largas len no vale 0!
		EVP_CIPHER_CTX_free(ctx);
		return Error("EVP_DecryptFinal_ex() failure");
	}
	plaintext_password_len += len;
	(*plaintext_password)[plaintext_password_len] = '\0';
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

static int print_info(void *data, int argc, char **argv, char **colNames){

	char *pass;
   	for(int i=0; i<argc; i++) {
	   	if(strcmp(colNames[i],"password_value")) {
			printf("%s => %s\n", colNames[i], argv[i]);
			continue;
	   	}
		char *cipher = argv[i] ? &(argv[i])[3] : ""; // no necesitamos los 3 primeros bytes aka 'V10' o 'V11'
		if(aes_decrypt(&pass,data,(unsigned char *)cipher,strlen(cipher)) != 0) {
			free(pass);
			exit(1);
		}
		printf("%s => %s\n", colNames[i], pass);
		free(pass);
   }
   putchar('\n');
   return 0;
}
/**
 * si data es NULL entonces invocamos UB
 */
int get_chrome_passwords(const char *path_db, void *data) {
	sqlite3 *db;
	char *error;
	int ret = 0;
	if(sqlite3_open_v2(path_db,&db,SQLITE_OPEN_READONLY,NULL)) {
		ret = Error(sqlite3_errmsg(db));
		goto clear;
	}
	const char *sql = "SELECT action_url, username_value, password_value FROM logins;";
	ret = sqlite3_exec(db, sql, print_info, data, &error);
   	if (ret != SQLITE_OK)
	{
		ret = Error(error);
		sqlite3_free(error);
	}
	clear:
	sqlite3_close(db);
	return ret;
}

bool dir_exist(const char *dir_name)
{
    struct stat sb;
    return !stat(dir_name, &sb) && S_ISDIR(sb.st_mode);
}

char *chrome_path(const char *home) {
	#define CHROME_PATH ".config/google-chrome/"
	#define CHROME_DB_PATH "Default/Login Data"
	#define ABSOLUTE_PATH_CHROME CHROME_PATH CHROME_DB_PATH
	size_t len = strlen(home)+strlen(ABSOLUTE_PATH_CHROME)+2; // 1 for NUL and other for '/'
	char *path = malloc(len);
	snprintf(path,len,"%s/%s",home,CHROME_PATH);
                          
	if(!dir_exist(path)) {
		free(path);
		return NULL;
	}
	size_t new_len = strlen(path);
	snprintf(&path[new_len],len-new_len,"%s",CHROME_DB_PATH);
	return path;
}

char *chromium_path(const char *home) {
	#define CHROMIUM_PATH ".config/chromium/"
	#define ABSOLUTE_PATH_CHROMIUM CHROMIUM_PATH CHROME_DB_PATH 
	size_t len = strlen(home)+strlen(ABSOLUTE_PATH_CHROMIUM)+2; // 1 for NUL and other for '/'
	char *path = malloc(len);
	snprintf(path,len,"%s/%s",home,CHROMIUM_PATH);
                          
	if(!dir_exist(path)) {
		free(path);
		return NULL;
	}
	size_t new_len = strlen(path);
	snprintf(&path[new_len],len-new_len,"%s",CHROME_DB_PATH);
	return path;	
}

char *chromium_snap_path(const char *home) {

	#define CHROMIUM_SNAP_PATH "snap/chromium/current/"
	#define ABSOLUTE_PATH_CHROMIUM_SNAP CHROMIUM_SNAP_PATH ABSOLUTE_PATH_CHROMIUM
	size_t len = strlen(home)+strlen(ABSOLUTE_PATH_CHROMIUM_SNAP)+2; // 1 for NUL and other for '/'
	char *path = malloc(len);
	snprintf(path,len,"%s/%s",home,CHROMIUM_SNAP_PATH);
                          
	if(!dir_exist(path)) {
		free(path);
		return NULL;
	}
	size_t new_len = strlen(path);
	snprintf(&path[new_len],len-new_len,"%s",ABSOLUTE_PATH_CHROMIUM);
	return path;	
}

/**
 * Un maldito dolor de cabeza soportar chromium.. Si lo instalamos desde
 * el centro de software de ubuntu, la ruta habrá que ir a buscarla a
 * ~/snap/chromium; sin embargo, si lo instalamos desde la web oficial de chromim estará en $HOME
 * Chrome es más fácil, está en ~/.config
 */ 
char *choose_path(const char *browser) {

	const char *home = getenv("HOME");
	assert(home);
	if(!strcmp(browser,"chrome")) {
		return chrome_path(home);
	}
	else if(!strcmp(browser,"chromium")) {
		return chromium_path(home);
	}
	else if(!strcmp(browser,"chromium-snap")) {
		return chromium_snap_path(home);
	}
	else
		assert(0 && "browser no soportado");

	return NULL;
}

int main() {

	const char *browser = "chrome";
	char *from = choose_path(browser);
	assert(from); // lo más probable es que el navegador solicitado no exista
	const char *to = "copia.db";
	if(!copy_file_in_chunks(from,to)) {
		free(from);
		return Error("No se pudo copiar la db");
	}
	free(from);
	if(!strcmp(browser,"chromium-snap"))
		browser = "chromium";
	unsigned char cipher[16] = {0};
	size_t bufferlen = sizeof(cipher);
	if(get_cipher(cipher, bufferlen,browser)) {
		return EXIT_FAILURE;
	}
	
	get_chrome_passwords(to, cipher);

	if(unlink(to)) {
		 return Error("No se pudo borrar el archivo");
	}
    return 0;
}