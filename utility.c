#include "utility.h"

/*
 * Helper function to convert hexadecimal strings to
 * integers of base 10
 */
int hex_to_int(char num)
{
    if (num >= 97)
    {
      num -= 32;
    }
    int first = num / 16 - 3;
    int second = num % 16;
    int result = first * 10 + second;
    if (result > 9)
    {
      result -= 1;
    }
    return result;
}

/*
 * Helper function to convert hexadecimal numbers into their
 * standard ASCII characters. This will be useful when we
 * converting our decrypted data back into a textual message
 */
int hex_to_ascii(const char num1, const char num2)
{
	int high = hex_to_int(num1) * 16;
	int low = hex_to_int(num2);
	return high + low;
}

/*
 * Helper function to print out hex numbers as strings
 * to the console
 */
void printHX(const char* string)
{
	int length = strlen(string);
	if (length % 2 != 0)
   {
		printf("%s\n", "invalid hex length");
		return;
	}
	int i;
	char buffer = 0;
	for(i = 0; i < length; i+=1) {
		if(i % 2 != 0)
			printf("%c", hex_to_ascii(buffer, string[i]));
		else
		    buffer = string[i];
	}
	printf("\n");
}

/*
 * Helper function to print out our big numbers
 */
void printBN(char* message, BIGNUM * big_num)
{
    char * number_str = BN_bn2hex(big_num);
    printf("%s 0x%s\n", message, number_str);
    OPENSSL_free(number_str);
}
