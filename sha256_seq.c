#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/sha.h>

#define PASSLEN 5           // Longueur du mot de passe
#define NR_PROC 4           // Nombre de processeurs ou threads
#define SHA_STRING_LEN 64   // Longueur du hachage SHA-256 en Hexa

typedef unsigned char byte;

// Fonction pour comparer deux hachages
int matches(byte *a, byte *b) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        if (a[i] != b[i])
            return 0;
    return 1;
}

// Convertit une chaîne hexadécimale (notre entree) en tableau d'octet (pour qu'on peut la compare avec un hachage)
byte* StringToByteArray(const char *s) {
    byte *hash = (byte*) malloc(SHA256_DIGEST_LENGTH);
    char two[3];
    two[2] = 0;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        two[0] = s[i * 2];
        two[1] = s[i * 2 + 1];
        hash[i] = (byte)strtol(two, NULL, 16);
    }
    return hash;
}

// Affiche le mot de passe trouvee ainsi que son hachage sha 
void afficherResultat(byte* password, byte* hash) {
    char sPass[PASSLEN + 1];
    memcpy(sPass, password, PASSLEN);
    sPass[PASSLEN] = 0;
    printf("\nMot de passe trouve : %s\nHachage : ", sPass);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        printf("%02x", hash[i]);
    printf("\n");
}

int main() {
    char buffer[SHA_STRING_LEN + 1]; // Contient l'entree : le hachage cible

    // Demande d'entrée utilisateur pour le hachage cible
    printf("Entrez le hachage SHA-256 \"64 caracteres hexadecimaux\" : ");
    scanf("%64s", buffer);

    // Conversion du hachage en tableau d'octets pour faciliter la comparaison 
    byte *target_hash = StringToByteArray(buffer);
    clock_t start_time = clock();

    // Attaque par force brute séquentielle
    int found = 0;
    for (int i = 0; i < 26 && !found; i++) {
        byte password[PASSLEN] = { 97 + i }; //1er caractere
        for (password[1] = 97; password[1] < 123 && !found; password[1]++) {   
            // 97 : valeur ASCII de 'a'  , 122 : valeur ASCII de 'z'
            for (password[2] = 97; password[2] < 123 && !found; password[2]++) {
                for (password[3] = 97; password[3] < 123 && !found; password[3]++) {
                    for (password[4] = 97; password[4] < 123 && !found; password[4]++) {
                        byte hash[SHA256_DIGEST_LENGTH];  // Pour stocker le resultat du hachage 
                        SHA256(password, PASSLEN, hash);  // Calculer le hachage
                        if (matches(target_hash, hash)) { // Comparer entre le hachage cible et le hachage actuel
                            afficherResultat(password, hash);
                            found = 1;
                        }
                    }
                }
            }
        }
    }
    free(target_hash);
    clock_t end_time = clock();
    
    // Calcul du temps écoulé
    double elapsed_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    if (!found) {
        printf("Mot de passe non trouve.\n");
    }

    // Afficher le temps d'exécution
    printf("Temps d'execution : %.2f secondes\n", elapsed_time);

    return 0;
}
