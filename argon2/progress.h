#ifndef AIRGAP_ARGON2_PROGRESS_H
#define AIRGAP_ARGON2_PROGRESS_H

#include <stdint.h>

typedef void (*airgap_argon2_progress_callback)(uint32_t completed, uint32_t total);
void airgap_argon2_set_progress(airgap_argon2_progress_callback callback);

#endif
