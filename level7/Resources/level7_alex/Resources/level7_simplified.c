#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Buffer global pour stocker le contenu du fichier .pass
char c[80];

// Structure représentant un élément avec un identifiant et un pointeur vers une chaîne
typedef struct {
    int id;
    char *str;
} element_t;

// Fonction qui affiche le contenu du buffer global avec un timestamp
int m() {
    time_t t = time(0);
    return printf("%s - %d\n", c, t);
}

// Fonction principale
int main(int argc, const char **argv) {
    element_t *elem1, *elem2;
    FILE *file;

    // Allocation de la première structure
    elem1 = malloc(sizeof(element_t));
    elem1->id = 1;
    elem1->str = malloc(8);

    // Allocation de la deuxième structure
    elem2 = malloc(sizeof(element_t));
    elem2->id = 2;
    elem2->str = malloc(8);

    // Copie des arguments dans les structures (VULNÉRABILITÉ: pas de vérification de taille)
    strcpy(elem1->str, argv[1]);
    strcpy(elem2->str, argv[2]);

    // Lecture du fichier .pass dans le buffer global
    file = fopen("/home/user/level8/.pass", "r");
    fgets(c, 68, file);
    
    puts("~~");
    return 0;
}

