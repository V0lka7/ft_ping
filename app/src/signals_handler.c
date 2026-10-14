#include "signals_handler.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

volatile int v_quit = 1;
volatile int v_alarm = 1;

static void quit_handler(int signo, siginfo_t *info, void *context);
static void alarm_handler(int signo, siginfo_t *info, void *context);
static int init_quit_signals();
static int init_alarm_signal();

int init_signals_handler() {
    if (init_quit_signals() == -1 || init_alarm_signal() == -1)
        return -1;
    return 0;
}

static int init_quit_signals() {
    struct sigaction act = {0};
    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = &quit_handler;
    if (sigaction(SIGQUIT, &act, NULL) == -1 ||
        sigaction(SIGINT, &act, NULL) == -1) {
        perror("ft_ping: ");
        return -1;
    }
    return 0;
}

static int init_alarm_signal() {
    struct sigaction act = {0};
    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = &alarm_handler;
    if (sigaction(SIGALRM, &act, NULL) == -1) {
        perror("ft_ping: ");
        return -1;
    }
    return 0;
}

static void quit_handler(int signo, siginfo_t *info, void *context) {
    // todo: Call the function which prints the statistic
    // clean the necessary thing

    (void)signo;
    (void)info;
    (void)context;
    v_quit = 0;
}

static void alarm_handler(int signo, siginfo_t *info, void *context) {
    // todo: Call the function which prints the statistic
    // clean the necessary thing

    (void)signo;
    (void)info;
    (void)context;
    v_alarm = 1;
}
