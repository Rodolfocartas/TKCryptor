//
//  TKAESCCMCryptor.m
//
//  Created by Taras Kalapun on 10/25/14.
//

#import "TKAESCCMCryptor.h"
#import <CommonCrypto/CommonCrypto.h>

@implementation TKAESCCMCryptor

static NSUInteger aesccm_ivLength = 12;
static size_t aesccm_tagLength = 8;

+ (NSData *)encrypt:(NSData *)data withKey:(NSData *)key iv:(NSData *)iv
{
    NSMutableData *cipher = [NSMutableData dataWithBytes:data.bytes length:(data.length + aesccm_tagLength)];
    
    size_t outLength;
    CCCryptorStatus status = ccm_aes_encrypt(key.bytes, iv.bytes, data.bytes, data.length, cipher.mutableBytes, &outLength);
    
    if (status != kCCSuccess) {
        NSLog(@"ccm_aes_crypt error: %i", status);
        return nil;
    }
    return cipher;
}

CCCryptorStatus aes_encrypt(const void *key, unsigned char *bytes, unsigned char *cipher) {
    size_t length = kCCBlockSizeAES128;
    size_t outLength;
    CCCryptorStatus result = CCCrypt(kCCEncrypt,
                                     kCCAlgorithmAES,
                                     kCCOptionECBMode,
                                     key,
                                     kCCKeySizeAES256,
                                     NULL,
                                     bytes,
                                     length,
                                     cipher,
                                     length,
                                     &outLength);
    
    if (result != kCCSuccess) {
        NSLog(@"AES128 Encryption Error");
    }
    return result;
}

#pragma mark - CCM


CCCryptorStatus ccm_aes_encrypt(const void *key,
                                const void *iv,
                                const void *dataIn,
                                size_t dataInLength,
                                void *dataOut,
                                size_t *dataOutMoved)
{
    size_t aesccm_LLength = 3;
    ccm_encrypt_message(key, aesccm_tagLength, aesccm_LLength, (unsigned char *)iv, (unsigned char *)dataOut, dataInLength, NULL, 0);
    return 0;
}

#define CCM_BLOCKSIZE kCCBlockSizeAES128

#define CCM_FLAGS(A,M,L) (((A > 0) << 6) | (((M - 2)/2) << 3) | (L - 1))

#define CCM_MASK_L(_L) ((1 << 8 * _L) - 1)

#define CCM_SET_COUNTER(A,L,cnt,C) {					\
int i;								\
memset((A) + CCM_BLOCKSIZE - (L), 0, (L));			\
(C) = (cnt) & CCM_MASK_L(L);						\
for (i = CCM_BLOCKSIZE - 1; (C) && (i > (L)); --i, (C) >>= 8)	\
(A)[i] |= (C) & 0xFF;						\
}

// XORs `n` bytes byte-by-byte starting at `y` to the memory area starting at `x`.
static inline void
ccm_memxor(unsigned char *x, const unsigned char *y, size_t n) {
    while(n--) {
        *x ^= *y;
        x++; y++;
    }
}

static inline void
ccm_block0(size_t M,       /* number of auth bytes */
           size_t L,       /* number of bytes to encode message length */
           size_t la,      /* l(a) octets additional authenticated data */
           size_t lm,      /* l(m) message length */
           unsigned char nonce[CCM_BLOCKSIZE],
           unsigned char *result) {
    int i;
    
    result[0] = CCM_FLAGS(la, M, L);
    
    /* copy the nonce */
    memcpy(result + 1, nonce, CCM_BLOCKSIZE - L);
    
    for (i=0; i < L; i++) {
        result[15-i] = lm & 0xff;
        lm >>= 8;
    }
}

static inline void
ccm_encrypt_xor(const void *key, size_t L, unsigned long counter,
                unsigned char *msg, size_t len,
                unsigned char A[CCM_BLOCKSIZE],
                unsigned char S[CCM_BLOCKSIZE]) {
    
    static unsigned long counter_tmp;
    
    CCM_SET_COUNTER(A, L, counter, counter_tmp);
    aes_encrypt(key, A, S);
    ccm_memxor(msg, S, len);
}

static inline void
ccm_mac(const void *key,
        unsigned char *msg, size_t len,
        unsigned char B[CCM_BLOCKSIZE],
        unsigned char X[CCM_BLOCKSIZE]) {
    size_t i;
    
    for (i = 0; i < len; ++i)
        B[i] = X[i] ^ msg[i];
    
    aes_encrypt(key, B, X);
    
}

/**
 * Authenticates and encrypts a message using AES in CCM mode. Please
 * see also RFC 3610 for the meaning of  M,  L,  lm and  la.
 *
 * @param key The AES key
 * @param M   The number of authentication octets.
 * @param L   The number of bytes used to encode the message length.
 * @param N   The nonce value to use. You must provide  CCM_BLOCKSIZE
 *            nonce octets, although only the first  16 -  L are used.
 * @param msg The message to encrypt. The first  la octets are additional
 *            authentication data that will be cleartext. Note that the
 *            encryption operation modifies the contents of  msg and adds
 *             M bytes MAC. Therefore, the buffer must be at least
 *             lm +  M bytes large.
 * @param lm  The actual length of  msg.
 * @param aad A pointer to the additional authentication data (can be  NULL if
 *             la is zero).
 * @param la  The number of additional authentication octets (may be zero).
 * @return length
 */
size_t
ccm_encrypt_message(const void *key, size_t M, size_t L,
                    unsigned char nonce[CCM_BLOCKSIZE],
                    unsigned char *msg, size_t lm,
                    const unsigned char *aad, size_t la) {
    size_t i, len;
    unsigned long counter_tmp;
    unsigned long counter = 1; /// @bug does not work correctly on ia32 when lm >= 2^16
    unsigned char A[CCM_BLOCKSIZE]; /* A_i blocks for encryption input */
    unsigned char B[CCM_BLOCKSIZE]; /* B_i blocks for CBC-MAC input */
    unsigned char S[CCM_BLOCKSIZE]; /* S_i = encrypted A_i blocks */
    unsigned char X[CCM_BLOCKSIZE]; /* X_i = encrypted B_i blocks */
    
    len = lm;			/* save original length */
    /* create the initial authentication block B0 */
    ccm_block0(M, L, la, lm, nonce, B);
    
    // We don't use auth data
    //_add_auth_data(key, aad, la, B, X);
    aes_encrypt(key, B, X);
    memset(B, 0, CCM_BLOCKSIZE);
    
    /* initialize block template */
    A[0] = L-1;
    
    // copy the nonce
    memcpy(A + 1, nonce, CCM_BLOCKSIZE - L);
    
    while (lm >= CCM_BLOCKSIZE) {
        // calculate MAC
        ccm_mac(key, msg, CCM_BLOCKSIZE, B, X);
        
        // encrypt
        ccm_encrypt_xor(key, L, counter, msg, CCM_BLOCKSIZE, A, S);
        
        // update local pointers
        lm -= CCM_BLOCKSIZE;
        msg += CCM_BLOCKSIZE;
        counter++;
    }
    
    if (lm) {
        /* Calculate MAC. The remainder of B must be padded with zeroes, so
         * B is constructed to contain X ^ msg for the first lm bytes (done in
         * mac() and X ^ 0 for the remaining CCM_BLOCKSIZE - lm bytes
         * (i.e., we can use memcpy() here).
         */
        memcpy(B + lm, X + lm, CCM_BLOCKSIZE - lm);
        ccm_mac(key, msg, lm, B, X);
        
        // encrypt
        ccm_encrypt_xor(key, L, counter, msg, lm, A, S);
        
        // update local pointers
        msg += lm;
    }
    
    // calculate S_0
    CCM_SET_COUNTER(A, L, 0, counter_tmp);
    aes_encrypt(key, A, S);
    
    for (i = 0; i < M; ++i)
        *msg++ = X[i] ^ S[i];
    
    return len + M;
}

//NSData *dh(unsigned char *d) {
//    return [NSData dataWithBytes:d length:kCCBlockSizeAES128];
//}


@end
