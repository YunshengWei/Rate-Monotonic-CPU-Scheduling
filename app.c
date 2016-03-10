#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>

static pid_t pid;
FILE *file;
const char delim[2] = ",";

void _register(unsigned long period, unsigned long processing_time) {
    fprintf(file, "R,%d,%lu,%lu", pid, period, processing_time);
    fflush(file);
}

void _yield(void) {
    fprintf(file, "Y,%d", pid);
    fflush(file);
}

void _deregister(void) {
    fprintf(file, "D,%d", pid);
    fflush(file);
}

bool _is_registered() {
    char *line = NULL;
    size_t len = 0;
    char *token;
    char *ptr;
    unsigned long read_pid;

    while (getline(&line, &len, file) != -1) {
        token = strtok(line, delim);
        read_pid = strtoul(token, &ptr, 10);

        if (read_pid == pid) {
            return true;
        }
    }
    return false;
}

void _signal_handler(int sig) {
    _deregister();
    fclose(file);
    exit(EXIT_SUCCESS);
}

void _do_job(int n) {
    unsigned long long fact = 0;
    for (int i = 1; i <=n; i++) {
        fact += i;
    }
    printf("fact: %llu\n", fact);
}

int main(int argc, char *argv[]) {
    if (SIG_ERR == signal(SIGINT, _signal_handler)) {
        fprintf(stderr, "Error when setting signal handler\n");
        exit(EXIT_FAILURE);
    }

    if (argc != 5) {
        fprintf(stderr, "Usage:\n\tapp [n: add to] [m: times] [period] [processing_time]\n");
        exit(EXIT_FAILURE);
    }

    int n = atoi(argv[1]);
    int m = atoi(argv[2]);
    unsigned long period = strtoul(argv[3], NULL, 0);
    unsigned long processing_time = strtoul(argv[4], NULL, 0);

    pid = getpid();

    file = fopen("/proc/mp2/status", "r+");
    _register(period, processing_time);
    if (!_is_registered()) {
        fprintf(stderr, "Fail to register %d\n", pid);
        exit(EXIT_FAILURE);
    }

    _yield();
    struct timeval wakeup_time;
    int i = 0;
    while (i++ <= m) {
        gettimeofday(&wakeup_time, NULL);
        printf("%d wakeup time: %ld(s)%ld(us)\n", pid, wakeup_time.tv_sec, wakeup_time.tv_usec);
        _do_job(n);
        _yield();
    }

    _deregister();
    fclose(file);
    return 0;
}