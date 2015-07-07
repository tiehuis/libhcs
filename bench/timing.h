#define _POSIX_C_SOURCE 199309L
#include <time.h>
#include <stdio.h>

#define CLOCK_TYPE CLOCK_REALTIME

#define TIME_CODE(msg, code)\
    do {\
        printf("Timing: %s\n", msg);\
        struct timespec _ts_start, _ts_end, _ts_calc;\
        clock_gettime(CLOCK_TYPE, &_ts_start);\
        code\
        clock_gettime(CLOCK_TYPE, &_ts_end);\
        if (_ts_end.tv_nsec - _ts_start.tv_nsec < 0) {\
            _ts_calc.tv_sec = _ts_end.tv_sec - _ts_start.tv_sec - 1;\
            _ts_calc.tv_nsec = 1e9 + _ts_end.tv_nsec - _ts_start.tv_nsec;\
        }\
        else {\
            _ts_calc.tv_sec = _ts_end.tv_sec - _ts_start.tv_sec;\
            _ts_calc.tv_nsec = _ts_end.tv_nsec - _ts_start.tv_nsec;\
        }\
        printf("Elapsed:\n\t%lus %juns\n\n", _ts_calc.tv_sec, _ts_calc.tv_nsec);\
    } while (0)
