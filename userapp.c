#include "userapp.h"
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char* argv[])
{
    int sum = 1;
    int count = 1;
    pid_t pid = getpid();
    
    FILE *fp = fopen("/proc/mp1/status", "w");
    fprintf(fp, "%d", pid);
    fclose(fp);
    
    
    while (1)
    {
        sum *= count;
        count++;
    }
//    sleep(10);
	return 0;
}

