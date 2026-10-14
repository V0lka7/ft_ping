#ifndef SIGNALS_HANDLER_H
#define SIGNALS_HANDLER_H

extern volatile int v_quit;
extern volatile int v_alarm;

int init_signals_handler();

#endif
