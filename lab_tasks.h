#ifndef __LAB_TASKS_H_
#define __LAB_TASKS_H_


#include <openssl/bn.h>
#include "utility.h"

/* Function Prototypes */
void task1(void);
void task2(void);
void task3(void);
void task4(void);
void task5(void);
void task6(void);
BIGNUM* getRSAPrivateKey(BIGNUM* p, BIGNUM* q, BIGNUM* e);
BIGNUM* encryptUsingRSA(BIGNUM* message, BIGNUM* modulo, BIGNUM* public_key);
BIGNUM* decryptUsingRSA(BIGNUM* e_message, BIGNUM* private_key, BIGNUM* public_key);

#endif
