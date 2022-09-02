#include <string.h>
#include <stdlib.h>
#include <locale.h>
#include "util.h"
#include "util_linux.h"
#include "use_gpgme.h"
#include "command_line.h"
#include "gestor_contrasenas.h" 

int main(int argc, char **argv)
{
    setlocale(LC_ALL,"");
    open_password_store();
    int return_code = 0;
    const char *arg = parse_argv(argc,argv);
    if(arg == NULL) { // si no es un comando válido
        return -1;
    }

    if(!strcmp("clear",arg)) {
        return reenter_passphrase();
    }
    else if(!strcmp("help",arg)) {
        return show_usage(argv);
    }
    else if(!strcmp("rm",argv[1])) {
        return delete_file(argv[2]);
    }
    else if(!strcmp("rename",argv[1])) {
        return change_name(argv[2],argv[3]);
    }
    char *pstore = get_store_dir();
    if(!strcmp("ls",arg)) {
        return_code = listar_archivos(pstore);
        free(pstore);
        return return_code;
    }
    if (!strcmp("new",argv[1])) {
        return_code = insert_entry(pstore,argv[2],false);
    }
    else if (!strcmp("get", argv[1])) {
        return_code = get_entry(pstore,argv[2],false);
    }
    else if(!strcmp("view",argv[1])) {
        return_code = get_entry(pstore,argv[2],true);
    }
    else if(!strcmp("update",argv[1])) {
        return_code = insert_entry(pstore,argv[2],true);
    }
    else if(!strcmp("check-pwned",argv[1])) {
        return_code = check_pwned(pstore);
    }

    cleanup_crypto();
    free(pstore);

    return return_code;
}