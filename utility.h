#ifndef __UTIL_H_
#define __UTIL_H_


#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

int hex_to_int(char num);
int hex_to_ascii(const char num1, const char num2);
void printHX(const char* string);
void printBN(char* message, BIGNUM* big_num);
#endif
