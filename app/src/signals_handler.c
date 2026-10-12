#include "signals_handler.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

volatile int g_quit = 1;

static void exit_handler(int signo, siginfo_t *info, void *context);

void init_signals_handler() {
    struct sigaction act = {0};
    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = &exit_handler;
    if (sigaction(SIGQUIT, &act, NULL) == -1 ||
        sigaction(SIGINT, &act, NULL) == -1) {
        perror("ft_ping: ");
        exit(1);
    }
}

static void exit_handler(int signo, siginfo_t *info, void *context) {
    // todo: Call the function which prints the statistic
    // clean the necessary thing

    (void)signo;
    (void)info;
    (void)context;
    g_quit = 0;
}
