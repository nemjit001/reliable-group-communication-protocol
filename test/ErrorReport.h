#ifndef ERR_REPORT

#define ErrorReport(msg) ({ \
    perror(msg);            \
    exit(1);                \
})

#endif
