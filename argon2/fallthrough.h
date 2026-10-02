#ifndef AIRGAP_ARGON2_FALLTHROUGH_H
#define AIRGAP_ARGON2_FALLTHROUGH_H

#if defined(__has_attribute)
#if __has_attribute(fallthrough)
#define AIRGAP_FALLTHROUGH __attribute__((fallthrough))
#endif
#endif
#ifndef AIRGAP_FALLTHROUGH
#define AIRGAP_FALLTHROUGH ((void)0)
#endif

#endif
