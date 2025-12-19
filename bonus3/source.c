#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * Programme vulnérable avec manipulation de chaîne de caractères.
 * 
 * Le programme prend un argument:
 *   - argv[1]: un nombre qui détermine où placer un null terminator dans le buffer
 * 
 *   1. Lit le fichier /home/user/end/.pass (66 bytes)
 *   2. Place un null terminator à la position 65
 *   3. Place un null terminator à la position argv[1] (converti en int)
 *   4. Lit 65 bytes supplémentaires à partir de la position 66
 *   5. Compare le début du buffer (jusqu'au null terminator à argv[1]) avec argv[1]
 *   6. Si égal, lance un shell
 *   7. Sinon, affiche le contenu à partir de la position 66
 * 
 * VULNÉRABILITÉ:
 *   - On peut contrôler où le null terminator est placé via argv[1]
 *   - Cela permet de contrôler quelle partie du fichier .pass est comparée
 *   - L'objectif est de trouver la bonne valeur pour argv[1] qui fait correspondre
 *     le début du buffer (jusqu'à ce null terminator) avec argv[1] lui-même
 */
int main(int argc, const char **argv) {
    char buffer[132];  // Buffer de 132 bytes
    FILE *file;
    
    // Ouvre le fichier contenant le mot de passe
    file = fopen("/home/user/end/.pass", "r");
    
    // Initialise le buffer à zéro
    memset(buffer, 0, sizeof(buffer));
    
    // Vérifie que le fichier est ouvert et qu'on a un argument
    if (!file || argc != 2)
        return -1;
    
    // Lit 66 bytes (0x42) depuis le fichier dans le buffer
    fread(buffer, 1, 0x42, file);
    
    // Place un null terminator à la position 65
    buffer[65] = 0;
    
    // VULNÉRABILITÉ: Place un null terminator à la position spécifiée par argv[1]
    // Cela permet de contrôler quelle partie du buffer sera comparée
    buffer[atoi(argv[1])] = 0;
    
    // Lit 65 bytes supplémentaires (0x41) à partir de la position 66
    fread(&buffer[66], 1, 0x41, file);
    
    // Ferme le fichier
    fclose(file);
    
    // Compare le début du buffer (jusqu'au null terminator à argv[1]) avec argv[1]
    // Si égal, lance un shell
    if (!strcmp(buffer, argv[1]))
        execl("/bin/sh", "sh", 0);
    else
        // Sinon, affiche le contenu à partir de la position 66
        puts(&buffer[66]);
    
    return 0;
}

