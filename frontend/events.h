#ifndef VCRYPTO_GUEST_FE_EVENTS_H
#define VCRYPTO_GUEST_FE_EVENTS_H

#include <stdbool.h>
#include <openssl/async.h>

bool vcrypto_setup_async_event_notify(int *be_async_fd);
bool vcrypto_clear_async_event_notify();
bool vcrypto_pause_job(ASYNC_JOB* job);
bool vcrypto_wake_job(ASYNC_JOB* job);

#endif // VCRYPTO_GUEST_FE_EVENTS_H
