#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Fonction qui lance un shell - c'est l'objectif de l'exploitation
void o(void)
{
    system("/bin/sh");
    _exit(1);
}

// Fonction vulnérable avec format string
void n(void)
{
    char s[520];
    
    // Lit 512 caractères depuis stdin
    fgets(s, 512, stdin);
    
    // VULNÉRABILITÉ: printf avec une chaîne non formatée
    // Permet une attaque de format string
    printf(s);
    
    exit(1);
}

int main(int argc, char **argv)
{
    n();
    return 0;
}

