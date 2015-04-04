#ifndef TIMING_H
#define TIMING_H

double timing_current_cpu_time(void);

#define timing_begin(init_code)\
    {\
        init_code\
        double time_init, time_curr;\
        time_init = timing_current_cpu_time();

#define timing_end(cleanup_code)\
        time_curr = timing_current_cpu_time();\
        printf("%fs\n", time_curr - time_init);\
        cleanup_code\
    }

#endif
