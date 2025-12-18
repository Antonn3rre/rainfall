#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Caractère séparateur inséré entre les deux entrées utilisateur.
// Dans le binaire original, il vient de la donnée globale `unk_80486A4`.
static const char SEPARATOR = ' ';

/**
 * Lit une ligne depuis stdin, l’affiche avec un prompt,
 * enlève le '\n' final et copie au plus 20 caractères dans dest.
 *
 * ATTENTION : pas de terminaison explicite par '\0' si la ligne fait 20+ chars.
 */
char *p(char *dest, const char *prompt) {
    char buf[0x1000];  // 4096 octets

    puts(prompt);                   // affiche le prompt
    ssize_t n = read(0, buf, 0x1000);
    if (n <= 0) {
        dest[0] = '\0';
        return dest;
    }

    // Remplacer le '\n' par '\0' s'il existe
    char *nl = strchr(buf, '\n');
    if (nl != NULL) {
        *nl = '\0';
    }

    // Copie au plus 20 caractères dans dest
    return strncpy(dest, buf, 20);
}

/**
 * Demande deux chaînes à l’utilisateur, les assemble dans dest:
 *   dest = "<première_chaine><SEPARATOR><deuxième_chaine>"
 *
 * VULNÉRABILITÉS :
 *   - pas de contrôle de taille sur dest (strcpy + strcat)
 *   - buffer dest dans main trop petit par rapport au pire cas
 */
char *pp(char *dest) {
    char first[20];
    char second[20];

    p(first,  " - ");
    p(second, " - ");

    // dest = first
    strcpy(dest, first);

    // Ajout du séparateur (2 octets écrits: SEPARATOR et le suivant inchangé)
    size_t len = strlen(dest);
    dest[len] = SEPARATOR;
    dest[len + 1] = '\0';  // pour être propre, on force le '\0'

    // Concatène second à la suite
    return strcat(dest, second);
}

int main(void) {
    char s[42];

    pp(s);
    puts(s);

    return 0;
}