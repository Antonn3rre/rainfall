#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PART1   40   // comme strncpy(..., argv[1], 0x28)
#define MAX_PART2   32   // comme strncpy(..., &dest[40], 0x20)
#define MAX_BUF     76   // taille totale des buffers v4 / dest dans le binaire

static int language = 0;  // 0 = anglais, 1 = finnois, 2 = néerlandais

static void init_language_from_env(void)
{
    const char *lang = getenv("LANG");
    if (!lang)
        return;

    if (memcmp(lang, "fi", 2) == 0) {
        language = 1;
    } else if (memcmp(lang, "nl", 2) == 0) {
        language = 2;
    }
}

static void greetuser(const char *name)
{
    char buf[128];  // plus grand que dans le binaire pour rester simple ici

    switch (language) {
        case 1:
            // Dans le binaire, c'est encodé en brut; on met une version lisible.
            strcpy(buf, "Hyvää päivää! ");
            break;
        case 2:
            strcpy(buf, "Goedemiddag! ");
            break;
        case 0:
        default:
            strcpy(buf, "Hello ");
            break;
    }

    strcat(buf, name);
    puts(buf);
}

int main(int argc, char **argv)
{
    char dest[MAX_BUF];
    char copy[MAX_BUF];

    if (argc != 3)
        return 1;

    memset(dest, 0, sizeof(dest));

    // recopie tronquée comme dans le binaire
    strncpy(dest,        argv[1], MAX_PART1);
    strncpy(dest + 40,   argv[2], MAX_PART2);

    init_language_from_env();

    // dans le binaire : qmemcpy(v4, dest, sizeof(v4));
    memcpy(copy, dest, sizeof(copy));

    // dans la décompil, greetuser reçoit bizarrement v4[0],
    // mais le comportement attendu est de saluer la chaîne complète.
    greetuser(copy);

    return 0;
}