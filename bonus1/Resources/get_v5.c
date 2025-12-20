#include <stdio.h>

int main(void) {
	int input = 0;
    int result = 0;
    
    // On récupére la premiere valeur de input pour laquelle input * 4 n'est pas 
    // - inférieur ou égal à zero : pour pouvoir l'utiliser comme size de memcpy() 
    // - et n'est pas supérieur à 64 : pour pouvoir overflow facilement
    
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
