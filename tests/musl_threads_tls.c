#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static __thread int tls_counter = 0;

static void* worker(void* arg) {
    long id = (long)arg;
    for (int i = 0; i < 100000; i++) {
        tls_counter++;
    }
    char buf[128];
    snprintf(buf, sizeof(buf), "thread=%ld tls=%d", id, tls_counter);
    return strdup(buf);
}

int main(void) {
    pthread_t t1, t2;
    if (pthread_create(&t1, NULL, worker, (void*)1L) != 0) return 2;
    if (pthread_create(&t2, NULL, worker, (void*)2L) != 0) return 3;

    char* r1 = NULL;
    char* r2 = NULL;
    pthread_join(t1, (void**)&r1);
    pthread_join(t2, (void**)&r2);

    printf("%s\n%s\n", r1 ? r1 : "null", r2 ? r2 : "null");

    free(r1);
    free(r2);
    return 0;
}
