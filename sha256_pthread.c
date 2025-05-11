#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <openssl/sha.h>

#define PASSLEN 5           // Longueur du mot de passe

#define ALPHABET_SIZE 26    // Lettres de 'a' à 'z'
#define SHA_STRING_LEN 64   // Longueur du hachage SHA-256 en Hexa
#define NBR_TH 4  // Nombre de threads

typedef unsigned char byte;

// Variable globale pour indiquer si le mot de passe est trouvé
int found_password = 0;

// Variable globale pour synchroniser l'attribution d'intervalle 
pthread_mutex_t alphabet_mutex = PTHREAD_MUTEX_INITIALIZER; 
int current_position = 0;

// Structure pour passer des arguments à la fonction des threads
typedef struct {
    byte *target_hash; // Hachage cible
    int thread_id; // NUMERO du thread
    int start;         // Début de l'intervalle d'alphabet
    int end;           // Fin de l'intervalle d'alphabet
} ThreadData;

// Fonction pour comparer deux hachages
int matches(byte *a, byte *b) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        if (a[i] != b[i])
            return 0;
    return 1;
}

// Convertit une chaîne hexadécimale en tableau d'octets
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

// Affiche le mot de passe trouvé ainsi que son hachage SHA et l'ID du thread
void afficherResultat(byte* password, byte* hash, pthread_t thread_id) {
    char sPass[PASSLEN + 1];
    memcpy(sPass, password, PASSLEN);
    sPass[PASSLEN] = 0;
    printf("\nMot de passe trouve : %s\nHachage : ", sPass);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        printf("%02x", hash[i]);
    printf("\nTrouve par le thread NUMERO : %lu\n", thread_id); // Affiche l'ID du thread
}

// Fonction du thread
void* threadFunction(void* arg) {
    ThreadData* data = (ThreadData*)arg;
    byte password[PASSLEN];
    byte hash[SHA256_DIGEST_LENGTH];
    
    int start, end;
    
    // Boucle principale pour traiter plusieurs intervalles
    while (!found_password) {
        // Section critique pour obtenir le prochain intervalle
        pthread_mutex_lock(&alphabet_mutex);

        // Si toutes les lettres ont été traitées, on sort
        if (current_position >= ALPHABET_SIZE) {
            pthread_mutex_unlock(&alphabet_mutex);
            break;
        }

        // Allouer un intervalle de lettres à ce thread
        start = current_position;
        end = current_position + (ALPHABET_SIZE / NBR_TH);
        if (end > ALPHABET_SIZE) end = ALPHABET_SIZE; // Ajuster pour ne pas dépasser la fin
        current_position = end;

        pthread_mutex_unlock(&alphabet_mutex);

        // Traitement du mot de passe dans cet intervalle
        for (int i = start; i < end && !found_password; i++) {
            password[0] = 97 + i; // Premier caractère
            
            for (password[1] = 97; password[1] < 123 && !found_password; password[1]++) {
                for (password[2] = 97; password[2] < 123 && !found_password; password[2]++) {
                    for (password[3] = 97; password[3] < 123 && !found_password; password[3]++) {
                        for (password[4] = 97; password[4] < 123 && !found_password; password[4]++) {
                            SHA256(password, PASSLEN, hash);
                            if (matches(data->target_hash, hash)) {
                                afficherResultat(password, hash, data->thread_id); // Passer l'ID du thread
                                found_password = 1; // Mot de passe trouvé
                                return NULL; // Quitter le thread immédiatement
                            }
                        }
                    }
                }
            }
        }
    }
    return NULL;
}

int main() {
    // Demande d'entrée utilisateur pour le hachage cible
    printf("Entrez le hachage SHA-256 (64 caracteres hexadecimaux) : ");
    char buffer[SHA_STRING_LEN + 1]; // Contiendra l'entrée : le hachage cible
    scanf("%64s", buffer);
    
    // Conversion du hachage en tableau d'octets
    byte *target_hash = StringToByteArray(buffer);

    // Initialiser les structures pour le temps
    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    // Création des threads
    pthread_t threads[NBR_TH];
    ThreadData threadData[NBR_TH];
    
    // Initialisation des threads
    for (int i = 0; i < NBR_TH; i++) {
        threadData[i].target_hash = target_hash;
        threadData[i].thread_id = i+1 ; // Stocker le numero du thread
        threadData[i].start = i * (ALPHABET_SIZE / NBR_TH); 
        threadData[i].end = (i == NBR_TH- 1) ? ALPHABET_SIZE : (i + 1) * (ALPHABET_SIZE / NBR_TH);
        pthread_create(&threads[i], NULL, threadFunction, &threadData[i]);
    }

    // Attendre que tous les threads se terminent ou s'arrêtent si le mot de passe est trouvé
    for (int i = 0; i < NBR_TH; i++) {
        pthread_join(threads[i], NULL);
    }

    // Enregistrer le temps de fin
    clock_gettime(CLOCK_MONOTONIC, &end_time);

    // Calculer le temps écoulé
    double elapsed_time = (end_time.tv_sec - start_time.tv_sec) +
                          (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
    
    // Afficher le temps d'exécution
    printf("Temps d'execution : %.3f secondes\n", elapsed_time);

    // Vérification si le mot de passe n'a pas été trouvé
    if (!found_password) {
        printf("Mot de passe non trouve.\n");
    }

    free(target_hash);
    return 0;
}