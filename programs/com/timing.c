#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

double timing_current_cpu_time(void)
{
    struct timespec cpu_time;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_time);
    return cpu_time.tv_sec + cpu_time.tv_nsec/1.0e9;
}
