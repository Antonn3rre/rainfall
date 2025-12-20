#include <stdio.h>
#include <stdlib.h>

// Fonction cachée qui sera appelée si l'exécution est détournée (ret2libc / ROP / etc.)
void run(void) {
    fwrite("Good... Wait what?\n", 1, 0x13, stdout);
    system("/bin/sh");   // Lance un shell
}

// Point d'entrée principal vulnérable
int main(int argc, char **argv) {
    char buffer[64];

    // Vulnérabilité : lecture sans limite, débordement de pile possible
    gets(buffer);

    return 0;
}