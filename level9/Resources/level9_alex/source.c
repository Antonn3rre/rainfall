/*
 * Ce programme crée deux objets de type N et utilise une vtable (table de fonctions virtuelles)
 * pour appeler des opérateurs. Il y a une vulnérabilité dans setAnnotation qui permet
 * d'écraser la vtable d'un objet adjacent.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Structure représentant un objet N
// Taille totale: 108 bytes (0x6C)
typedef struct {
    int (**vtable)(int, int);  // Offset 0: pointeur vers la vtable (4 bytes)
    char annotation[100];      // Offset 4-103: zone de données (100 bytes)
    int value;                 // Offset 104: valeur entière (4 bytes)
} N;

// Opérateur + : additionne les valeurs des deux objets
// Les paramètres sont des pointeurs vers les objets (castés en int)
int N_operator_plus(int obj1, int obj2) {
    int *val1 = (int *)(obj1 + 104);  // Récupère la valeur à l'offset 104
    int *val2 = (int *)(obj2 + 104);
    return *val1 + *val2;
}

// Opérateur - : soustrait les valeurs des deux objets
int N_operator_minus(int obj1, int obj2) {
    int *val1 = (int *)(obj1 + 104);
    int *val2 = (int *)(obj2 + 104);
    return *val1 - *val2;
}

// Table de fonctions virtuelles (vtable)
// Contient les pointeurs vers les opérateurs + et -
int (*vtable[])(int, int) = {
    N_operator_plus,   // Index 0
    N_operator_minus   // Index 1
};

// Constructeur de N
void N_constructor(N *this, int val) {
    this->vtable = vtable;  // Initialise le pointeur vers la vtable
    this->value = val;      // Stocke la valeur à l'offset 104
}

// Méthode pour définir l'annotation
// VULNÉRABILITÉ: Pas de vérification de la longueur de la chaîne !
// Peut écrire au-delà de la zone annotation et écraser la vtable de l'objet suivant
void N_setAnnotation(N *this, char *s) {
    size_t len = strlen(s);
    memcpy((char *)this + 4, s, len);  // Copie à l'offset 4 sans vérification de taille
}

int main(int argc, char **argv) {
    if (argc <= 1) {
        _exit(1);
    }
    
    // Alloue deux objets N sur le tas (108 bytes chacun)
    N *obj1 = (N *)malloc(0x6C);  // 108 bytes
    N_constructor(obj1, 5);        // Objet 1 avec valeur 5
    
    N *obj2 = (N *)malloc(0x6C);  // 108 bytes
    N_constructor(obj2, 6);        // Objet 2 avec valeur 6
    
    // Définit l'annotation de obj1 avec argv[1]
    // VULNÉRABILITÉ: Si argv[1] est trop long, cela peut écraser la vtable de obj2
    // (si obj2 est alloué juste après obj1 en mémoire)
    N_setAnnotation(obj1, argv[1]);
    
    // Appelle la première fonction de la vtable de obj2
    // La vtable est à l'offset 0, donc obj2->vtable[0] est operator+
    // Signature: int (*)(int, int) où les int sont des pointeurs vers objets
    return obj2->vtable[0]((int)obj2, (int)obj1);
}

