#include <stdio.h>
#include <stdlib.h>

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

// Point d'entrée du programme
int main(int argc, char **argv, char **envp)
{
    return v();
}

