#ifndef ARGON2_H
#define ARGON2_H

#include <stdint.h>
#include <stddef.h>
#include <limits.h>

#if defined(__cplusplus)
extern "C" {
#endif

 
#ifdef A2_VISCTL
#define ARGON2_PUBLIC __attribute__((visibility("default")))
#define ARGON2_LOCAL __attribute__ ((visibility ("hidden")))
#elif defined(_MSC_VER)
#define ARGON2_PUBLIC __declspec(dllexport)
#define ARGON2_LOCAL
#else
#define ARGON2_PUBLIC
#define ARGON2_LOCAL
#endif

 



 
#define ARGON2_MIN_LANES UINT32_C(1)
#define ARGON2_MAX_LANES UINT32_C(0xFFFFFF)

 
#define ARGON2_MIN_THREADS UINT32_C(1)
#define ARGON2_MAX_THREADS UINT32_C(0xFFFFFF)

 
#define ARGON2_SYNC_POINTS UINT32_C(4)

 
#define ARGON2_MIN_OUTLEN UINT32_C(4)
#define ARGON2_MAX_OUTLEN UINT32_C(0xFFFFFFFF)

 
#define ARGON2_MIN_MEMORY (2 * ARGON2_SYNC_POINTS)  

#define ARGON2_MIN(a, b) ((a) < (b) ? (a) : (b))
 
#define ARGON2_MAX_MEMORY_BITS                                                 \
    ARGON2_MIN(UINT32_C(32), (sizeof(void *) * CHAR_BIT - 10 - 1))
#define ARGON2_MAX_MEMORY                                                      \
    ARGON2_MIN(UINT32_C(0xFFFFFFFF), UINT64_C(1) << ARGON2_MAX_MEMORY_BITS)

 
#define ARGON2_MIN_TIME UINT32_C(1)
#define ARGON2_MAX_TIME UINT32_C(0xFFFFFFFF)

 
#define ARGON2_MIN_PWD_LENGTH UINT32_C(0)
#define ARGON2_MAX_PWD_LENGTH UINT32_C(0xFFFFFFFF)

 
#define ARGON2_MIN_AD_LENGTH UINT32_C(0)
#define ARGON2_MAX_AD_LENGTH UINT32_C(0xFFFFFFFF)

 
#define ARGON2_MIN_SALT_LENGTH UINT32_C(8)
#define ARGON2_MAX_SALT_LENGTH UINT32_C(0xFFFFFFFF)

 
#define ARGON2_MIN_SECRET UINT32_C(0)
#define ARGON2_MAX_SECRET UINT32_C(0xFFFFFFFF)

 
#define ARGON2_DEFAULT_FLAGS UINT32_C(0)
#define ARGON2_FLAG_CLEAR_PASSWORD (UINT32_C(1) << 0)
#define ARGON2_FLAG_CLEAR_SECRET (UINT32_C(1) << 1)

 

extern int FLAG_clear_internal_memory;

 
typedef enum Argon2_ErrorCodes {
    ARGON2_OK = 0,

    ARGON2_OUTPUT_PTR_NULL = -1,

    ARGON2_OUTPUT_TOO_SHORT = -2,
    ARGON2_OUTPUT_TOO_LONG = -3,

    ARGON2_PWD_TOO_SHORT = -4,
    ARGON2_PWD_TOO_LONG = -5,

    ARGON2_SALT_TOO_SHORT = -6,
    ARGON2_SALT_TOO_LONG = -7,

    ARGON2_AD_TOO_SHORT = -8,
    ARGON2_AD_TOO_LONG = -9,

    ARGON2_SECRET_TOO_SHORT = -10,
    ARGON2_SECRET_TOO_LONG = -11,

    ARGON2_TIME_TOO_SMALL = -12,
    ARGON2_TIME_TOO_LARGE = -13,

    ARGON2_MEMORY_TOO_LITTLE = -14,
    ARGON2_MEMORY_TOO_MUCH = -15,

    ARGON2_LANES_TOO_FEW = -16,
    ARGON2_LANES_TOO_MANY = -17,

    ARGON2_PWD_PTR_MISMATCH = -18,     
    ARGON2_SALT_PTR_MISMATCH = -19,    
    ARGON2_SECRET_PTR_MISMATCH = -20,  
    ARGON2_AD_PTR_MISMATCH = -21,      

    ARGON2_MEMORY_ALLOCATION_ERROR = -22,

    ARGON2_FREE_MEMORY_CBK_NULL = -23,
    ARGON2_ALLOCATE_MEMORY_CBK_NULL = -24,

    ARGON2_INCORRECT_PARAMETER = -25,
    ARGON2_INCORRECT_TYPE = -26,

    ARGON2_OUT_PTR_MISMATCH = -27,

    ARGON2_THREADS_TOO_FEW = -28,
    ARGON2_THREADS_TOO_MANY = -29,

    ARGON2_MISSING_ARGS = -30,

    ARGON2_ENCODING_FAIL = -31,

    ARGON2_DECODING_FAIL = -32,

    ARGON2_THREAD_FAIL = -33,

    ARGON2_DECODING_LENGTH_FAIL = -34,

    ARGON2_VERIFY_MISMATCH = -35
} argon2_error_codes;

 
typedef int (*allocate_fptr)(uint8_t **memory, size_t bytes_to_allocate);
typedef void (*deallocate_fptr)(uint8_t *memory, size_t bytes_to_allocate);

 

 
























typedef struct Argon2_Context {
    uint8_t *out;     
    uint32_t outlen;  

    uint8_t *pwd;     
    uint32_t pwdlen;  

    uint8_t *salt;     
    uint32_t saltlen;  

    uint8_t *secret;     
    uint32_t secretlen;  

    uint8_t *ad;     
    uint32_t adlen;  

    uint32_t t_cost;   
    uint32_t m_cost;   
    uint32_t lanes;    
    uint32_t threads;  

    uint32_t version;  

    allocate_fptr allocate_cbk;  
    deallocate_fptr free_cbk;    

    uint32_t flags;  
} argon2_context;

 
typedef enum Argon2_type {
  Argon2_d = 0,
  Argon2_i = 1,
  Argon2_id = 2
} argon2_type;

 
typedef enum Argon2_version {
    ARGON2_VERSION_10 = 0x10,
    ARGON2_VERSION_13 = 0x13,
    ARGON2_VERSION_NUMBER = ARGON2_VERSION_13
} argon2_version;

 





ARGON2_PUBLIC const char *argon2_type2string(argon2_type type, int uppercase);

 




ARGON2_PUBLIC int argon2_ctx(argon2_context *context, argon2_type type);

 














ARGON2_PUBLIC int argon2i_hash_encoded(const uint32_t t_cost,
                                       const uint32_t m_cost,
                                       const uint32_t parallelism,
                                       const void *pwd, const size_t pwdlen,
                                       const void *salt, const size_t saltlen,
                                       const size_t hashlen, char *encoded,
                                       const size_t encodedlen);

 













ARGON2_PUBLIC int argon2i_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                                   const uint32_t parallelism, const void *pwd,
                                   const size_t pwdlen, const void *salt,
                                   const size_t saltlen, void *hash,
                                   const size_t hashlen);

ARGON2_PUBLIC int argon2d_hash_encoded(const uint32_t t_cost,
                                       const uint32_t m_cost,
                                       const uint32_t parallelism,
                                       const void *pwd, const size_t pwdlen,
                                       const void *salt, const size_t saltlen,
                                       const size_t hashlen, char *encoded,
                                       const size_t encodedlen);

ARGON2_PUBLIC int argon2d_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                                   const uint32_t parallelism, const void *pwd,
                                   const size_t pwdlen, const void *salt,
                                   const size_t saltlen, void *hash,
                                   const size_t hashlen);

ARGON2_PUBLIC int argon2id_hash_encoded(const uint32_t t_cost,
                                        const uint32_t m_cost,
                                        const uint32_t parallelism,
                                        const void *pwd, const size_t pwdlen,
                                        const void *salt, const size_t saltlen,
                                        const size_t hashlen, char *encoded,
                                        const size_t encodedlen);

ARGON2_PUBLIC int argon2id_hash_raw(const uint32_t t_cost,
                                    const uint32_t m_cost,
                                    const uint32_t parallelism, const void *pwd,
                                    const size_t pwdlen, const void *salt,
                                    const size_t saltlen, void *hash,
                                    const size_t hashlen);

 
ARGON2_PUBLIC int argon2_hash(const uint32_t t_cost, const uint32_t m_cost,
                              const uint32_t parallelism, const void *pwd,
                              const size_t pwdlen, const void *salt,
                              const size_t saltlen, void *hash,
                              const size_t hashlen, char *encoded,
                              const size_t encodedlen, argon2_type type,
                              const uint32_t version);

 






ARGON2_PUBLIC int argon2i_verify(const char *encoded, const void *pwd,
                                 const size_t pwdlen);

ARGON2_PUBLIC int argon2d_verify(const char *encoded, const void *pwd,
                                 const size_t pwdlen);

ARGON2_PUBLIC int argon2id_verify(const char *encoded, const void *pwd,
                                  const size_t pwdlen);

 
ARGON2_PUBLIC int argon2_verify(const char *encoded, const void *pwd,
                                const size_t pwdlen, argon2_type type);

 







ARGON2_PUBLIC int argon2d_ctx(argon2_context *context);

 







ARGON2_PUBLIC int argon2i_ctx(argon2_context *context);

 








ARGON2_PUBLIC int argon2id_ctx(argon2_context *context);

 






ARGON2_PUBLIC int argon2d_verify_ctx(argon2_context *context, const char *hash);

 






ARGON2_PUBLIC int argon2i_verify_ctx(argon2_context *context, const char *hash);

 






ARGON2_PUBLIC int argon2id_verify_ctx(argon2_context *context,
                                      const char *hash);

 
ARGON2_PUBLIC int argon2_verify_ctx(argon2_context *context, const char *hash,
                                    argon2_type type);

 



ARGON2_PUBLIC const char *argon2_error_message(int error_code);

 









ARGON2_PUBLIC size_t argon2_encodedlen(uint32_t t_cost, uint32_t m_cost,
                                       uint32_t parallelism, uint32_t saltlen,
                                       uint32_t hashlen, argon2_type type);

#if defined(__cplusplus)
}
#endif

#endif
