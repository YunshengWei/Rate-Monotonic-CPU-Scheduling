#include "userapp.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdbool.h>


static pid_t pid;
FILE *file;

// register job: R, pid, period, processing time
void _register_(unsigned long period, unsigned long processing_time) {
    fprintf(file, "R,%d,%lu,%lu", pid, period, processing_time);
}

// yield: Y, pid
void yield(void) {
    fprintf(file, "Y,%d", pid);
}

// deregister job: D, pid
void deregister(void) {
    fprintf(file, "D,%d", pid);
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
    long fact = 1;
    for (int i = 1; i <=n; i++) {
        fact *= i;
    }
}

int main(int argc, char* argv[])
{
    if (SIG_ERR == signal(SIGINT, signal_handler)) {
        fprintf(stderr, "Error when setting signal handler\n");
        exit(EXIT_FAILURE);
    }

    if (argc != 4) {
        fprintf(stderr, "Usage:\n\tuserapp [n!] [period] [processing_time]\n");
        exit(EXIT_FAILURE);
    }

    int n = atoi(argv[1]);
    unsigned long period = strtoul(argv[2], NULL, 0);
    unsigned long processing_time = strtoul(argv[3], NULL, 0);

    pid = getpid();

    do_job(n);

    // file = fopen("/proc/mp2/status", "r+");
    // register job
    // _register_(period, processing_time);
    // ensure job pid is registered
    // if (!isRegistered()) {
    //     fprintf(stderr, "Fail to register\n");
    //     exit(EXIT_FAILURE);
    // }
    // ready to start
    // yield();

    // struct timeval wakeup_time;
    struct timeval start, end;
    gettimeofday (&start, NULL);

    // printf("%d wakeup time: %ld\n", pid, wakeup_time.tv_sec * 1000 + wakeup_time.tv_usec);
    do_job(n);
    gettimeofday (&end, NULL);
    long exe_time = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);
    printf("%d execution time in msec: %ld\n", pid, exe_time);
    // while (true) 
    // for (int i = 0; i<10; i++)
    // {
    //     gettimeofday(&wakeup_time, NULL);
    //     printf("%d wakeup time: %ld\n", pid, wakeup_time.tv_sec * 1000000 + wakeup_time.tv_usec);
    //     do_job(n);
    //     // block job
    //     yield();
    // }
    // deregister
    // deregister();

    // fclose(file);
    return 0;
}

