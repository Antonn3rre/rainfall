#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * Programme vulnérable avec buffer overflow sur la stack.
 * 
 * Le programme prend deux arguments:
 *   - argv[1]: un nombre (doit être <= 9)
 *   - argv[2]: une chaîne de caractères
 * 
 * VULNÉRABILITÉ:
 *   - Le buffer dest fait 40 bytes
 *   - On copie 4 * v5 bytes depuis argv[2] dans dest
 *   - Si v5 = 9, on copie 36 bytes (sans overflow)
 *   - MAIS: v5 est stocké juste après dest sur la stack
 *   - Si on peut écraser v5 via le memcpy, on peut contourner la vérification
 *   - L'objectif est de faire en sorte que v5 == 1464814662 après la copie
 *     pour déclencher execl("/bin/sh", "sh", 0)
 */
int main(int argc, const char **argv) {
    char dest[40];  // Buffer de 40 bytes sur la stack
    int v5;         // Variable stockée juste après dest sur la stack
    
    // Convertit le premier argument en entier
    v5 = atoi(argv[1]);
    
    // Vérifie que v5 <= 9
    if (v5 > 9)
        return 1;
    
    // Copie 4 * v5 bytes depuis argv[2] dans dest
    // VULNÉRABILITÉ: Si on peut écraser v5 (qui est après dest sur la stack),
    // on peut contourner la vérification v5 > 9 et atteindre la condition suivante
    memcpy(dest, argv[2], 4 * v5);
    
    // Condition impossible à atteindre normalement (v5 <= 9, mais 1464814662 > 9)
    // Mais si v5 a été écrasé par le memcpy précédent, cette condition peut être vraie
    if (v5 == 1464814662)
        execl("/bin/sh", "sh", 0);
    
    return 0;
}

