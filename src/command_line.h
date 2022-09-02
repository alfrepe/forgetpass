#pragma once
#include <stdio.h> // para size_t
#include <stdbool.h>
#define MAX_LEN_USERNAME 30
#define MAX_LEN_WEBSITE 30
#define USERNAME_POS 0
#define WEBSITE_POS 1
#define KEY_POS 2
#define GEN_PASSWORD_POS 3
#define EXTENSION_GPG ".gpg"
#define HAS_GPG_EXTENSION(str) strstr(str,EXTENSION_GPG)

struct sub_commands {
    // char *command;
    size_t size; // size of command_parameter
    char *command_parameter;
};

struct new_command {
    const char *register_name; // el nombre del registro, por ejemplo en new "gmail", ser� "gmail". Es argv[2]
    const char *keyname;
    struct sub_commands sub_commands[4]; // sub_commands[0] es "username", sub_commands[1] es "website", sub_commands[2] es "key", sub_commands[3] es "password_len"
    unsigned check_pwned;
    long password_len;
};

struct update_command {
    struct new_command *new_opts;
    unsigned update_password;
};

struct check_pwned_command {

    unsigned check_all_entries;
    const char *entry_name;
};

struct ls_command {
    unsigned sort_by_last_modified_date;
    unsigned only_name;
};

struct view_command {
    int view_password;
    int view_username;
    int view_website;
    int view_key;
    const char *registername;
};

bool is_empty(const char *command);  
bool is_valid_command(const char *actual_command, size_t index); // para 'new' y 'update'
bool string_to_long(const char *string, long *num);

int check_view_command(int argc, char **argv);
int optionals_for_view(int required_argc, int argc, char **argv);
void default_view_configuration(int required_argc);
bool is_view_command_repeated(int value);
void init_view_command(struct view_command* opt);

void init_update_command(struct update_command* opt);
int check_update_command(int argc, char **argv);
int optionals_for_update(int required_argc, int argc, char **argv);
void default_update_configuration(int required_argc);
int assign_index_for_required_update_commands(const char *actual_command, int *,size_t);
int parse_commands_take_one_argc_from_update(const char *command);

int check_ls_command(int argc, char **argv);
int optionals_for_ls(int required_argc, int argc, char **argv);
void init_ls_command(struct ls_command* opt);

void init_new_command(struct new_command *opt);
int check_new_command(int argc, char **argv);
int optionals_for_new(int required_argc, int argc, char **argv);
int assign_index_for_required_new_commands(const char *actual_command, int*, size_t);
int parse_commands_take_one_argc_from_new(const char *command);

int check_check_pwned_command(int argc, char **argv);
void show_ignore_commands(int error);
void init_check_pwned_command(struct check_pwned_command* opt);

int parse_commands_without_argc(const char *command);
int parse_commands_take_one_argc(const char *command);
int parse_commands_take_three_argc(const char *command);
int parse_commands_with_two_argc(const char *command);
int has_optionals_args_argv_without_argc(const char *command);
int has_optionals_args_argv_with_one_argc(const char *command);
int check_optionals_arg_from_without_argc(int argc, char **argv, const char *command);
int check_optionals_arg_from_with_two_argc(int argc, char **argv, const char *command);

const char *parse_argv(int argc, char **argv);

struct update_command update_opts;
struct new_command new_opts;
struct view_command view_opts;
struct check_pwned_command check_pwned_opts;
struct ls_command ls_opts;
