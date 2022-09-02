#ifndef HAVE_GETCH_H
#define HAVE_GETCH_H

#ifdef _WIN32

#include <conio.h>
#define getch() _getch()

#else

// Equivalente para el getch en *nix
// http://zobayer.blogspot.com.es/2010/12/getch-getche-in-gccg.html
int getch(void);
#include <unistd.h>
#include <termios.h>
#include <stdio.h>


#endif

#endif