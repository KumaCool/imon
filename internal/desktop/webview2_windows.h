#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
int infra_windows_run(uintptr_t, const char *, const char *, size_t, const char *, size_t, const char *, size_t);
void infra_windows_stop(void);
void infra_windows_alert(const char *);
void infra_windows_reply(const char *, const char *, size_t);
void infra_windows_choose(const char *);
void infra_windows_save(const char *, const char *, size_t);
#ifdef __cplusplus
}
#endif
