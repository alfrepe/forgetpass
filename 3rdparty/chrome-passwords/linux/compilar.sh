gcc $(pkg-config --cflags --libs libsecret-1) chrome.c -lsecret-1 -lglib-2.0 -lgobject-2.0 -lsqlite3 -g -Wall -lcrypto -fsanitize=address
#g++ -O3 -o lssecret lssecret.cpp -pthread -I/usr/local/include/libsecret-1 -I/usr/include/glib-2.0
# -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -L/usr/local/lib/x86_64-linux-gnu
#-lsecret-1 -lgio-2.0 -lgobject-2.0 -lglib-2.0
