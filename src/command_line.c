#include "command_line.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <assert.h>
#include <limits.h>

#define REQUIRED_ARGC_FOR_VIEW 3
#define REQUIRED_ARGC_FOR_UPDATE 3
#define REQUIRED_ARGC_FOR_NEW 5
//#define MINIUM_PASSWORD_LEN 30

static const size_t max_occurrences = 2; // para evitar repetidos
static const char *commands_without_argument[] = {"ls","clear","help","check-pwned"};
static const char *commands_with_only_optionals[] = {"check-pwned","ls"};
static const char *commands_take_one_argument[] = {"update","get","view","rm"};
static const char *commands_take_one_argument_has_optionals[] = {"update","view"};
static const char *commands_take_two_argument[] = {"rename"};
static const char *commands_take_three_argument[] = {"new"};
// comandos optativos para new que requieren un argumento obligatorio
static const char *commands_with_one_argument_from_new[] = {"username","website","gen"};
// comandos optativos para update que requieren un argumento obligatorio
static const char *commands_with_one_argument_from_update[] = {"username","website","key","gen"};
// comandos optativos para view
static const char *commands_optatives_from_view[] = {"-password","-username","-website","-key"};

#define OPTATIVE_WITH_ONE_ARGC_FOR_NEW     ARRAY_SIZE(commands_with_one_argument_from_new)
#define OPTATIVE_WITH_ONE_ARGC_FOR_UPDATE  ARRAY_SIZE(commands_with_one_argument_from_update)

int parse_commands_with_two_argc(const char *command) {
    return strarrp(commands_take_two_argument,command,ARRAY_SIZE(commands_take_two_argument));
}

int has_optionals_args_argv_without_argc(const char *command) {
    return strarrp(commands_with_only_optionals,command,ARRAY_SIZE(commands_with_only_optionals));
}
int has_optionals_args_argv_with_one_argc(const char *command) {
    return strarrp(commands_take_one_argument_has_optionals,command,ARRAY_SIZE(commands_take_one_argument_has_optionals));
}
int parse_commands_without_argc(const char *command) {
    return strarrp(commands_without_argument,command,ARRAY_SIZE(commands_without_argument));
}

int parse_commands_take_one_argc(const char *command) {
    return strarrp(commands_take_one_argument,command,ARRAY_SIZE(commands_take_one_argument));
}

int parse_commands_take_three_argc(const char *command) {
    return strarrp(commands_take_three_argument,command,ARRAY_SIZE(commands_take_three_argument));
}

int parse_commands_take_one_argc_from_new(const char *command) {
    return strarrp(commands_with_one_argument_from_new,command,ARRAY_SIZE(commands_with_one_argument_from_new));
}

int parse_commands_take_one_argc_from_update(const char *command) {
    return strarrp(commands_with_one_argument_from_update,command,ARRAY_SIZE(commands_with_one_argument_from_update));
}
bool is_empty(const char *command) {
    return (!command || *command == '\0');
}

bool string_to_long(const char *string, long *num) {
    const char *command_name = commands_with_one_argument_from_new[2];
    char *end;
    bool ret = false;
    long password_len = strtol(string,&end,10);
    if(*end != '\0') {
        fprintf(stderr,"The argument for '%s' must be an integer\n",command_name);
    }
    else if(password_len <= 0) { // tambi�n verificamos LONG_MIN 
         fprintf(stderr,"The argument for '%s' must be > 0\n",command_name);
    }
    else if(password_len == LONG_MAX || password_len > 100) { // TODO: MAX_PASSWORD_LEN es una macro en input.h
        fprintf(stderr,"Number too big for '%s'\n",command_name);
    }
    else {
        *num = password_len;
        ret = true;
    }
    return ret;
}


bool is_valid_command(const char *actual_command, size_t index) {
    bool valid = false;
    size_t size = new_opts.sub_commands[index].size;
    const char *string = new_opts.sub_commands[index].command_parameter;
    long password_len = 0;
    
    if(!string || !size) { // NOTA: como ya sabemos la longitud de la string, no llamo a is_empty() para ahorrarme un strlen
        fprintf(stderr, "'%s' cannot be empty\n",actual_command);
    }
    else if(has_any_space(string)) {
        fprintf(stderr, "'%s' cannot have spaces\n",actual_command);
    }
    else if(index == USERNAME_POS && size > MAX_LEN_USERNAME) {  // es el comando "username"
        fprintf(stderr, "'%s' cannot exceed %u characteres\n",actual_command, MAX_LEN_USERNAME);
    }
    else if(index == WEBSITE_POS && size > MAX_LEN_WEBSITE) {  // es el comando "website"
        fprintf(stderr, "'%s' cannot exceed %u characters\n",actual_command, MAX_LEN_WEBSITE);
    }
    else if(index == GEN_PASSWORD_POS && string_to_long(string,&password_len)) { // TODO: esto rompe la encapsulaci�n!!!!!!!!!!!!!! y es inadmisible
       new_opts.password_len = password_len;
        return true;
    }
    else
        valid = true;
    return valid;
}

int assign_index_for_required_new_commands(const char *actual_command, int *occurrences, size_t size_occurrences) {
    assert(size_occurrences == ARRAY_SIZE(commands_with_one_argument_from_new));
    int index = USERNAME_POS;

    if(!strcmp(actual_command,"username")) {
        ++(*occurrences);
    }
    else if(!strcmp(actual_command,"website")) {
        index = WEBSITE_POS; ++(occurrences[1]);
    }
    else if(!strcmp(actual_command,"gen")) {
        index = GEN_PASSWORD_POS; ++(occurrences[2]);
    }
    else
        BUG();

    for(size_t i = 0; i < size_occurrences; i++) {
        if(occurrences[i] == max_occurrences)
            index = -1;
    }
    return index;
}

int optionals_for_new(int required_argc, int argc, char **argv)
{
    int ocurrences[OPTATIVE_WITH_ONE_ARGC_FOR_NEW] = {0};
    const char *actual_command = NULL;
    bool is_repeated = false;

    for (;required_argc < argc && !is_repeated; required_argc++)
    {
        if (!parse_commands_take_one_argc_from_new(argv[required_argc]))
        {
            actual_command = argv[required_argc];
            int index = assign_index_for_required_new_commands(actual_command,ocurrences,OPTATIVE_WITH_ONE_ARGC_FOR_NEW);
            if(index < 0)
                is_repeated = true;
            else if (argc - required_argc == 1)
            {
                fprintf(stderr, "A required argument is missing for '%s'\n", actual_command);
                return -1;
            }
            else {
                new_opts.sub_commands[index].command_parameter = argv[++required_argc];
                new_opts.sub_commands[index].size = strlen(new_opts.sub_commands[index].command_parameter);
                if(!is_valid_command(actual_command,index)) {
                    return -1;
                }
            }
        }
        else if(!strcmp(argv[required_argc],"-nopwned")) {
            is_repeated = new_opts.check_pwned != 1; // -nopwned solo puede aparecer una vez
            new_opts.check_pwned = 0; actual_command = "-nopwned";
        }
        else
        {
            fprintf(stderr,"'%s' is unknown\n",argv[required_argc]);
            return -1;
        }
    }
    if(is_repeated) {
        fprintf(stderr, "'%s' is repeated\n",actual_command);
        return -1;
    }
    if(new_opts.sub_commands[GEN_PASSWORD_POS].command_parameter && new_opts.password_len == -1) {
        return -1;
    }
    return 0;
}

void init_new_command(struct new_command *opt) {

    opt->register_name = " ";
    opt->sub_commands[0].command_parameter = " ";
    opt->sub_commands[0].size = 1;
    opt->sub_commands[1].command_parameter = " ";
    opt->sub_commands[1].size = 1;
    opt->sub_commands[2].command_parameter = NULL; // inicializamos con NULL porque gpgme lo utiliza para seleccionar la clave automaticamente (creo que es la primera); de lo contrario toma la especificada por par�metro.
    opt->sub_commands[2].size = 0;
    opt->sub_commands[3].command_parameter = NULL;
    opt->sub_commands[3].size = 0;
    opt->check_pwned = 1;
    opt->keyname = " ";
    opt->password_len = -1;
}

int check_new_command(int argc, char **argv) {
    init_new_command(&new_opts);
    if(argc > 10) {
        fprintf(stderr, "Too many arguments for '%s'\n",argv[1]);
        return -1;
    }
    else if(is_empty(argv[2]) || is_all_space(argv[2])) {
        fprintf(stderr, "The first argument for '%s' is empty\n",argv[1]);
        return -1;
    }
    else if(0 != strcmp("key",argv[3])) {
        fprintf(stderr, "'key' is misssing as a third argument\n");
        return -1;
    }
    else if(HAS_GPG_EXTENSION(argv[2])) {
        fprintf(stderr, "Don't add '%s' extension, this is done automatically by the program\n",EXTENSION_GPG);
        return -1;
    }
    // assign key name
    new_opts.sub_commands[2].command_parameter = argv[4];
    /**
     * llegados a este punto los comandos obligatorios est�n satisfechos
     * comprobamos si hay algun optativo y si est�n bien formados
     */
    return optionals_for_new(REQUIRED_ARGC_FOR_NEW,argc,argv); // podr�a ignorar los comandos optativos inv�lidos...
}
/*
 * devuelve -1 si est� repetido, en caso contrario el index
 * occurrences[0] -> 'username'
 * occurrences[1] -> 'website'
 * occurrences[2] -> 'key'
 */
int assign_index_for_required_update_commands(const char *actual_command, int *occurrences, size_t size_occurrences) {
    assert(size_occurrences == ARRAY_SIZE(commands_with_one_argument_from_update));
    int index = USERNAME_POS;
    if(!strcmp(actual_command,"username"))
        ++(*occurrences);
    else if(!strcmp(actual_command,"website")) {
        index = WEBSITE_POS; ++(occurrences[1]);
    }
    else if(!strcmp(actual_command,"key")) {
        index = KEY_POS; ++(occurrences[2]);
    }
    else if(!strcmp(actual_command,"gen")) {
        index = GEN_PASSWORD_POS; ++(occurrences[3]);
    }
    else
        BUG();
    for(size_t i = 0; i < size_occurrences; i++)
        if(occurrences[i] == max_occurrences)
            index = -1;
    return index;
}
/*
 * Si no hay argumentos optativos, excepto que sea '-nopwned',
 * establecemos la configuraci�n por defecto: se preguntar� por la contrase?a
 * p.ej: './a.out update gmail" o './a.out update gmail -nopwned'
*/
void default_update_configuration(int required_argc)  {
    if(required_argc == REQUIRED_ARGC_FOR_UPDATE || (required_argc == 4 && !new_opts.check_pwned))
    {
        update_opts.update_password = 1;
    }
}

int optionals_for_update(int required_argc, int argc, char **argv)
{
    int occurrences[OPTATIVE_WITH_ONE_ARGC_FOR_UPDATE] = {0}; // ocurrencias de par�metros que requieren uno obligatorio
    const char *actual_command = NULL;
    bool is_repeated = false;

    for (;required_argc < argc && !is_repeated; required_argc++)
    {
        if (!parse_commands_take_one_argc_from_update(argv[required_argc]))
        {
            actual_command = argv[required_argc];
            int index = assign_index_for_required_update_commands(actual_command,occurrences,OPTATIVE_WITH_ONE_ARGC_FOR_UPDATE);
            if(index < 0)
                is_repeated = true;
            else if (argc - required_argc == 1)
            {
                fprintf(stderr, "A required argument is missing for '%s'\n", actual_command);
                return -1;
            }
            else {
                new_opts.sub_commands[index].command_parameter = argv[++required_argc];
                new_opts.sub_commands[index].size = strlen(new_opts.sub_commands[index].command_parameter);
                if(!is_valid_command(actual_command,index)) {
                    return -1;
                }
            }
        }
        else if(!strcmp(argv[required_argc],"-nopwned")) {
            is_repeated =  new_opts.check_pwned != 1; // -nopwned solo puede aparecer una vez
            new_opts.check_pwned = 0; actual_command = "-nopwned";
            
        }
        else if(!strcmp(argv[required_argc],"password")) {
            is_repeated = update_opts.update_password != 0; // password solo puede aparecer una vez
            update_opts.update_password = 1; actual_command = "password";
        }
        else
        {
            fprintf(stderr,"'%s' is unknown\n",argv[required_argc]);
            return -1;
        }
    }
    if(is_repeated) {
        fprintf(stderr, "'%s' is repeated\n",actual_command);
        return -1;
    }
     if(new_opts.sub_commands[GEN_PASSWORD_POS].command_parameter && new_opts.password_len == -1) {
        return -1;
    }
    default_update_configuration(required_argc);
    return 0;
}

void show_ignore_commands(int error) {
    if(error || update_opts.update_password) return;
    if(!new_opts.check_pwned) {
        printf("'-nopwned' will be ignored because 'password' was not specified\n");
    }
    if(new_opts.password_len != -1) {
        printf("'gen' will be ignored because 'password' was not specified\n");
    }
}

void init_update_command(struct update_command* opt) {
    opt->new_opts = &new_opts;
    init_new_command(opt->new_opts);
    opt->update_password = 0;
}

int check_update_command(int argc, char **argv) {
    init_update_command(&update_opts);
    if(argc > 11) {
        fprintf(stderr, "Too many arguments for '%s'\n",argv[1]);
        return -1;
    }
    else if(is_empty(argv[2]) || is_all_space(argv[2])) {
        fprintf(stderr, "The first argument for '%s' is empty\n",argv[1]);
        return -1;
    }
    else if(HAS_GPG_EXTENSION(argv[2])) {
        fprintf(stderr, "Don't add '%s' extension, this is done automatically by the program\n",EXTENSION_GPG);
        return -1;
    }
    /**
     * llegados a este punto los comandos obligatorios est�n satisfechos
     * comprobamos si hay algun optativo y si est�n bien formados
     */
    int ret = optionals_for_update(REQUIRED_ARGC_FOR_UPDATE,argc,argv); // podr�a ignorar los comandos optativos inv�lidos...
    show_ignore_commands(ret);
    return ret;
}

void default_view_configuration(int required_argc) {
    if(required_argc == REQUIRED_ARGC_FOR_VIEW) { // si no hay argumentos optativos establecemos la configuraci�n por defecto: se mostrar�n todos los campos
        view_opts.view_password = 0;
        view_opts.view_username = 1;
        view_opts.view_website = 2;
        view_opts.view_key = 3;
    }
}

bool is_view_command_repeated(int value) {
    return value != -1;
}

int optionals_for_view(int required_argc, int argc, char **argv)
{
    const char *actual_command = NULL;
    bool is_repeated = false;

    for (size_t pos = 0; required_argc < argc && !is_repeated; required_argc++, pos++)
    {
        if (!strcmp(argv[required_argc],commands_optatives_from_view[0]))
        {
            is_repeated = is_view_command_repeated(view_opts.view_password);
            view_opts.view_password = pos; // mostrarlos en el mismo orden en el que fueron recibidos
            actual_command = commands_optatives_from_view[0];
        }
        else if(!strcmp(argv[required_argc],commands_optatives_from_view[1])) {
            is_repeated =  is_view_command_repeated(view_opts.view_username);
            view_opts.view_username = pos;
            actual_command = commands_optatives_from_view[1];
        }
        else if(!strcmp(argv[required_argc],commands_optatives_from_view[2])) {
            is_repeated = is_view_command_repeated(view_opts.view_website); 
            view_opts.view_website = pos;
            actual_command = commands_optatives_from_view[2];
        }
        else if(!strcmp(argv[required_argc],commands_optatives_from_view[3])) {
            is_repeated = is_view_command_repeated(view_opts.view_key); 
            view_opts.view_key = pos;
            actual_command = commands_optatives_from_view[3];
        }
        else
        {
            fprintf(stderr,"'%s' is unknown\n",argv[required_argc]);
            return -1;
        }
    }
    if(is_repeated) {
        fprintf(stderr, "'%s' is repeated\n",actual_command);
        return -1;
    }
    default_view_configuration(required_argc);

    return 0;
}

void init_view_command(struct view_command* opt) {
    opt->view_password = -1;
    opt->view_username = -1;
    opt->view_website = -1;
    opt->view_key = -1;
}

int check_view_command(int argc, char **argv) {  // argc solo puede ser 3,4,5 o 6
    init_view_command(&view_opts);
    if(argc > 7) {
        fprintf(stderr, "Too many arguments for '%s'\n",argv[1]);
        return -1;
    }
    else if(HAS_GPG_EXTENSION(argv[2])) {
        fprintf(stderr, "Don't add '%s' extension, this is done automatically by the program\n",EXTENSION_GPG);
        return -1;
    }
    return optionals_for_view(REQUIRED_ARGC_FOR_VIEW,argc,argv);
}

void init_check_pwned_command(struct check_pwned_command* opt) {
    opt->check_all_entries = 0;
    opt->entry_name = " ";
}

int check_check_pwned_command(int argc, char **argv) {  // argc solo puede ser 2 o 3
    init_check_pwned_command(&check_pwned_opts);
    if(argc > 3) {
        fprintf(stderr, "Too many arguments for '%s'\n",argv[1]);
        return -1;
    }
    if(argc == 2) {
        check_pwned_opts.check_all_entries = 1;
        return 0;
    }
    if(HAS_GPG_EXTENSION(argv[2])) {
        fprintf(stderr, "Don't add '%s' extension, this is done automatically by the program\n",EXTENSION_GPG);
        return -1;
    }
    check_pwned_opts.entry_name = argv[2];
    
    return 0;
}

void init_ls_command(struct ls_command* opt) {
    opt->sort_by_last_modified_date = 0;
    opt->only_name = 0;
}

int optionals_for_ls(int required_argc, int argc, char **argv)
{
    init_ls_command(&ls_opts);
    const char *actual_command = NULL;
    bool is_repeated = false;
    for (size_t pos = 0; required_argc < argc && !is_repeated; required_argc++, pos++)
    {
        if (!strcmp(argv[required_argc],"last-modified"))
        {
            is_repeated = ls_opts.sort_by_last_modified_date != 0;
            ls_opts.sort_by_last_modified_date = 1;
            actual_command = "last-modified";
        }
        else if(!strcmp(argv[required_argc],"only-name")) {
            is_repeated = ls_opts.only_name != 0;
            ls_opts.only_name = 1;
            actual_command = "only-name";
        }
        else
        {
            fprintf(stderr,"'%s' is unknown\n",argv[required_argc]);
            return -1;
        }
    }
    if(is_repeated) {
        fprintf(stderr, "'%s' is repeated\n",actual_command);
        return -1;
    }
    return 0;
}

int check_ls_command(int argc, char **argv) {  // argc solo puede ser 2 o 3
    if(argc > 4) {
        fprintf(stderr, "Too many arguments for '%s'\n",argv[1]);
        return -1;
    }
    return optionals_for_ls(2,argc,argv);   
}

int check_optionals_arg_from_without_argc(int argc, char **argv, const char *command) {
    if(!strcmp(command,"check-pwned"))
        return check_check_pwned_command(argc,argv);
    if(!strcmp(command,"ls"))
        return check_ls_command(argc,argv);
    return -1;
}

int check_optionals_arg_from_with_two_argc(int argc, char **argv, const char *command) {
    if(!strcmp(command,"update"))
        return check_update_command(argc,argv);
    
    if(!strcmp(command,"view"))
        return check_view_command(argc,argv);
    return -1;
}

const char *parse_argv(int argc, char **argv) {
    
    if(argc < 2) { 
        fprintf(stderr,"No argument received, see '%s help'\n",argv[0] ? argv[0] : "null"); // argv[0] puede ser cero si argc es 0 y no estoy seguro si esto seria UB al desreferenciar el puntero nulo
        return NULL;
    }
    if(!parse_commands_without_argc(argv[1])) { // argc = 2
        if(!has_optionals_args_argv_without_argc(argv[1])) {
            if(check_optionals_arg_from_without_argc(argc,argv,argv[1]))
                return NULL;            
        }
        else if(argc > 2) {
            fprintf(stderr, "Too many arguments for '%s'\n",argv[1]);
            return NULL;
        }
    }
    else if(!parse_commands_with_two_argc(argv[1])) {
        if(argc == 2 || argc == 3) {
            fprintf(stderr,"Missing %d required arguments for '%s'\n",4-argc,argv[1]);
            return NULL;
        }
        else if(argc > 4) {
            fprintf(stderr, "Too many arguments for '%s'\n",argv[1]);
            return NULL;
        }
    }
    else if(!parse_commands_take_one_argc(argv[1])) { // argc = 3
        if(argc == 2) {
            fprintf(stderr, "Missing one required argument for '%s'\n",argv[1]);
            return NULL;
        }
        else if(!has_optionals_args_argv_with_one_argc(argv[1])) {
            if(check_optionals_arg_from_with_two_argc(argc,argv,argv[1])) {
                return NULL;
            }
        }
        else if(argc > 3) {                                         
            fprintf(stderr, "Too many arguments for '%s'\n",argv[1]);
            return NULL;
        }
    }
    else if(!parse_commands_take_three_argc(argv[1])) {
        if(argc <= 4) {
            fprintf(stderr,"Faltan %d argumentos obligatorio para '%s'\n", 5-argc,argv[1]);
            return NULL;
        }
        else if(check_new_command(argc,argv)) {
            return NULL;
        }
    }
    else {
        fprintf(stderr,"Invalid command\n");
        fprintf(stderr,"Print help using '%s help'\n",argv[0]);
        return NULL;
    }
    
    return argv[1];
}
