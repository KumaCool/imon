#pragma once

#include <stddef.h>
#include <stdint.h>

int infra_desktop_run(uintptr_t goState, const char *index, size_t indexSize,
                      const char *style, size_t styleSize, const char *script,
                      size_t scriptSize);
void infra_desktop_stop(void);
void infra_desktop_alert(const char *error);
void infra_desktop_reply(uintptr_t reply, const char *json, const char *error);
void infra_desktop_save(uintptr_t reply, const char *data, size_t size);
