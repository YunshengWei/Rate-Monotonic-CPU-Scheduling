#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdbool.h>

static pid_t pid;
FILE *file;

void _register_(unsigned long period, unsigned long processing_time) {
    fprintf(file, "R,%d,%lu,%lu", pid, period, processing_time);
    fflush(file);
}

void yield(void) {
    fprintf(file, "Y,%d", pid);
    fflush(file);
}

void deregister(void) {
    fprintf(file, "D,%d", pid);
    fflush(file);
}

bool isRegistered() {
    unsigned int i;
    while (fscanf(file, "%u", &i) != EOF) {
        if (i == pid) {
            return true;
        }
    }
    return false;
}

void signal_handler(int sig) {
    deregister();
    fclose(file);
    exit(EXIT_SUCCESS);
}

void do_job(int n) {
    unsigned long long fact = 1;
    for (int i = 1; i <=n; i++) {
        fact += i;
    }
    printf("fact: %llu\n", fact);
}

int main(int argc, char *argv[]) {
    if (SIG_ERR == signal(SIGINT, signal_handler)) {
        fprintf(stderr, "Error when setting signal handler\n");
        exit(EXIT_FAILURE);
    }

    if (argc != 5) {
        fprintf(stderr, "Usage:\n\tapp [n: jiadaoji] [m: cishu] [period] [processing_time]\n");
        exit(EXIT_FAILURE);
    }

    int n = atoi(argv[1]);
    int m = atoi(argv[2]);
    unsigned long period = strtoul(argv[3], NULL, 0);
    unsigned long processing_time = strtoul(argv[4], NULL, 0);

    pid = getpid();

    file = fopen("/proc/mp2/status", "r+");
    _register_(period, processing_time);
    if (!isRegistered()) {
        fprintf(stderr, "Fail to register %d\n", pid);
        exit(EXIT_FAILURE);
    }

    yield();
    struct timeval wakeup_time;
    int i = 0;
    while (i++ <= m) {
        gettimeofday(&wakeup_time, NULL);
        printf("%d wakeup time: %ld\n", pid, wakeup_time.tv_sec * 1000000 + wakeup_time.tv_usec);
        do_job(n);
        yield();
    }

    deregister();
    fclose(file);
    return 0;
}