#ifndef INFRA_GTK_LINUX_H
#define INFRA_GTK_LINUX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int infra_gtk_run(uintptr_t handle, const char *proof,
                  const void *index, size_t index_length,
                  const void *style, size_t style_length,
                  const void *script, size_t script_length);
void infra_gtk_stop(uintptr_t handle);
void infra_gtk_alert(const char *error);
void infra_gtk_reply(uintptr_t reply, const char *json, const char *error);
void infra_gtk_save(uintptr_t reply, const void *bytes, size_t length);

#ifdef __cplusplus
}
#endif
#endif
