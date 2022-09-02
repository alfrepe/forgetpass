# -std=gnu99 si no hay problemas con la funcion POSIX strdup ya que no es parte del estandar (-std=c99) al ser una funcion posix.
gcc src/linked_list.c src/gestor_contrasenas.c src/command_line.c src/input.c src/getch.c src/main.c src/use_gpgme.c src/util.c src/util_linux.c 3rdparty/libclipboard/lib/libclipboard.a -I ~/Escritorio/programacion/c/proyectos/forgetpass/3rdparty/libclipboard/include -Wall -lcurl -lgpgme -lsodium -lcrypto -lpthread -lxcb -g -std=gnu99 -fsanitize=address -Wmissing-prototypes -Wformat-security -Werror=vla
# -fsanitize=address
