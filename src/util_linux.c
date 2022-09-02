#include "util.h"
#include "util_linux.h"
#include "getch.h"
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <unistd.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

time_t get_time_last_modified(const char *path) {
    if (path)
    {
        struct stat st;
        if (!stat(path, &st))
        {
            return st.st_mtime;
        }
    }
    return 0;
}

int remove_file(const char *name)
{
    if (name == NULL)
        return -1;
    return unlink(name);
}
int leer_carpeta(const char *path, bool recursive, callback func_ptr)
{ 
    // PORTABLE
    int n_files = 0;
    assert(path);
    DIR *d = opendir(path);
    if (d == NULL)
    {
        return -1;
    }
    struct dirent *dir;
    while ((dir = readdir(d)) != NULL)
    {
        if (dir->d_type != DT_DIR)
        { 
            n_files += func_ptr(path,dir->d_name);
        }
        else if (recursive && strcmp(dir->d_name, ".") && strcmp(dir->d_name, ".."))
        { 
            // TODO: y n_files?
            char d_path[PATH_SIZE] = {0};
            sprintf(d_path, "%s/%s", path, dir->d_name);
            leer_carpeta(d_path, true,func_ptr);
        }
    }
    closedir(d);
    return n_files;
}

bool dir_exist(const char *dir_name)
{
    struct stat sb;
    return !stat(dir_name, &sb) && S_ISDIR(sb.st_mode);
}

bool create_dir(const char *dir_name)
{
    return !mkdir(dir_name, S_IRWXU);
}

bool file_exist(const char *file_name)
{
    return !access(file_name, F_OK) && !dir_exist(file_name);
}

void execute_program(char *const *argv)
{
    int status = 0;
    pid_t pid = fork();
    
    switch (pid)
    {
        case 0:
        {
            if(execvp(argv[0], argv) < 0) {
                error("Error: no se pudo ejecutar el comando\n");
                exit(1);
            }
            break;
                
        }
        case -1:
            error("Error: no se pudo lanzar un nuevo proceso\n");
            break;
        default:
            // Parent process
            while (wait(&status) != pid);
            if(!status) {
                puts("El comando se ejecut� con �xito!");
            }
    }
}