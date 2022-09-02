#include "util.h"
#include "util_win.h"
#include <SDKDDKVer.h> 
#include <stdio.h> 
#include <Windows.h> 
#include <bcrypt.h>     // Cryptography API
#include <assert.h>
#include <stdbool.h>
#include <time.h>
#include <locale.h>
#include <direct.h>
#include <sys/types.h>
#include <sys/stat.h>

void ClearCryptHashObjects(const crypto_handles *hand_crypto) {
    BCryptCloseAlgorithmProvider(hand_crypto->m_alg, 0);
    BCryptDestroyHash(hand_crypto->m_hash);

	/*if(BCryptCloseAlgorithmProvider(hand_crypto.m_alg, 0)) {
		fprintf(stderr,"BCryptCloseAlgorithmProvider()\n");
	}
	if(BCryptDestroyHash(hand_crypto.m_hash)) {
		fprintf(stderr,"BCryptDestroyHash()\n");
	} */

}

// Finalizes hash calculation. 
// After this method is called, hash value can be got using HashValue() method. 
// After this method is called, the HashData() method can't be called anymore. 
unsigned char *Sha1Hash(const char *data, size_t length, const crypto_handles *hand_crypto)
{
    // Hash digest string (hex) 
	static BYTE hashValue[20]; // SHA-1: 20 bytes = 160 bits EL ORO!
	// static unsigned char dest[sizeof(hashValue)*2] = {0};

    // Hash this chunk of data 
	if ( BCryptHashData(
		hand_crypto->m_hash, // hash object handle 
		(UCHAR*)data,    // safely remove const from buffer pointer 
		length, // input buffer length in bytes 
		0       // no flags 
	) != 0) {
        fprintf(stderr,"Can't hash data.");
        return NULL;
    }


	if ( BCryptFinishHash(
		hand_crypto->m_hash,             // handle to hash object 
		hashValue,          // output buffer for hash value 
		sizeof(hashValue),  // size of this buffer 
		0                   // no flags 
	) != 0) {
        fprintf(stderr,"Can't finalize hashing.\n");
        return NULL;
    }
	// convertimos a hexadecimal
	/*for (size_t i = 0; i < sizeof(hashValue); ++i)
	{
		sprintf(&dest[i * 2], "%02X", hashValue[i]); // TODO: cambiar por una mas segura?
	} */
	//printf("%s\n", dest);
	ClearCryptHashObjects(hand_crypto);

	return hashValue;
}

void InitializeCryptHashObjects(crypto_handles * hand_crypto)
{	
    hand_crypto->error = BCryptOpenAlgorithmProvider(
        &hand_crypto->m_alg,          // algorithm handle 
        BCRYPT_SHA1_ALGORITHM,      // hashing algorithm ID 
        NULL,                       // use default provider 
        0                           // default flags 
    );
	if(hand_crypto->error) {
        //fprintf(stderr,"Can't load default cryptographic algorithm provider.\n");
        return;
    }
    
	// GetDWordProperty(BCRYPT_OBJECT_LENGTH);
	// Create the hash object 
	hand_crypto->error = BCryptCreateHash(
		hand_crypto->m_alg,  // handle to parent 
		&hand_crypto->m_hash,            // hash object handle 
		NULL,   // hash object buffer pointer 
		0,   // hash object buffer length 
		NULL,            // no secret 
		0,                  // no secret 
		0                   // no flags 
	);
	if ( hand_crypto->error != 0) {
        //fprintf(stderr,"Can't create crypt hash object.\n");
		return;
    }
}

unsigned char *SHA1(const char* text,size_t len)
{
    crypto_handles hand_crypto;
	assert(text);
	// Create the hash object for the particular hashing 
	InitializeCryptHashObjects(&hand_crypto);
    if(hand_crypto.error) {
        fprintf(stderr,"Ocurrio un error en InitializeCryptHashObjects");
        return NULL;
    }
	// Finalize hashing 
	return Sha1Hash(text, len,&hand_crypto);
}

//////////////////////////////////////////////////////////////////////////////////////////////////
// Executes the given command using CreateProcess() and WaitForSingleObject().
// Returns FALSE if the command could not be executed or if the exit code could not be determined.
BOOL execute_program(const char *path,LPSTR cmdLine) // CUIDADO LAS RUTAS EN WINDOWS SON DIFERENTES A LAS DE LINUX!!!!
{
   PROCESS_INFORMATION processInformation = {0};
   STARTUPINFO startupInfo                = {0};
   startupInfo.cb                         = sizeof(startupInfo);

   // Create the process
   BOOL result = CreateProcess(path, cmdLine, 
                               NULL, NULL, FALSE, 
                               NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW, 
                               0, 0, &startupInfo, &processInformation);

   if (!result)
   {
      // CreateProcess() failed
      // Get the error from the system

      return FALSE;
   }
   else
   {
      // Successfully created the process.  Wait for it to finish.
      WaitForSingleObject( processInformation.hProcess, INFINITE );

      CloseHandle( processInformation.hProcess );
      CloseHandle( processInformation.hThread );
      return TRUE;
   }
}

int remove_file(const char *name) {
    return !DeleteFile(name);
} // DeleteFileA

bool dir_exist(const char *dir_name)
{
  DWORD attrib = GetFileAttributesA(dir_name);
  return !(attrib == INVALID_FILE_ATTRIBUTES) && (attrib & FILE_ATTRIBUTE_DIRECTORY);
}

bool create_dir(const char *dir_name) {
    return CreateDirectory(dir_name,NULL);
}

bool file_exist(const char *file_name)
{
  DWORD attrib = GetFileAttributesA(file_name);
  return !(attrib == INVALID_FILE_ATTRIBUTES) && !(attrib & FILE_ATTRIBUTE_DIRECTORY);
}
int leer_carpeta(const char *path, callback ptr)
{
    if(!path) return -1;
    int read_files = 0;
    char pathBuffer[MAX_PATH] = {0};
    if( strlen(path) > MAX_PATH-3) // para el /* y el \0
        return -1;
    snprintf(pathBuffer,strlen(path)+3,"%s%s",path,"/*");
    WIN32_FIND_DATA data;
    HANDLE hFind = FindFirstFile(pathBuffer, &data);
   
    if ( hFind != INVALID_HANDLE_VALUE ) {
        do {
           read_files += ptr(&data);
        } while (FindNextFile(hFind, &data));
        FindClose(hFind);
    }
    return read_files;
}

time_t get_time_last_modified(const char *path) {
    if (path)
    {
        struct _stat st;
        if (!_stat(path, &st))
        {
            return st.st_mtime;
        }
    }
    return 0;
}
// https://github.com/zodiacon/DotNextMoscow2019/blob/master/CoreClr/pal/src/file/filetime.cpp#L99
time_t FILETIME_to_time_t (FILETIME file_t) {
    #define SECS_BETWEEN_1601_AND_1970_EPOCHS 11644473600ULL
    #define SECS_TO_100NS 10000000ULL
    ULARGE_INTEGER ull;
	ull.LowPart = file_t.dwLowDateTime;
	ull.HighPart = file_t.dwHighDateTime;
	return ull.QuadPart / SECS_TO_100NS - SECS_BETWEEN_1601_AND_1970_EPOCHS;
}
