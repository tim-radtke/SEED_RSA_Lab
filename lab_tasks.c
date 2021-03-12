#include "lab_tasks.h"

/* HELPER FUNCTIONS FOR THE TASK FUNCTIONS */
/*
 * This is a helper function to derive the private key given (e, n)
 * as the private key.
 * @params: p, q, e <- all pointers to a BIGNUM
 * @return the private key as a BIGNUM
 *
 * To retrieve the private key we need to use modulo invers of p*q
 */
BIGNUM* getRSAPrivateKey(BIGNUM* p, BIGNUM* q, BIGNUM* e)
{
   /*Create the structure needed for the BIGNUMs*/
   BN_CTX *ctx = BN_CTX_new();
   /*setup our variables for the math*/
   BIGNUM* p_minus = BN_new();
   BIGNUM* q_minus = BN_new();
   BIGNUM* one = BN_new();
   BIGNUM* temp = BN_new();
   BN_dec2bn(&one, "1");
   BN_sub(p_minus, p, one);
   BN_sub(q_minus, q, one);
   BN_mul(temp, p_minus, q_minus, ctx);

   /* Now lets tackle the modulo inverse*/
   BIGNUM* result = BN_new();
   BN_mod_inverse(result, e, temp, ctx);
   /*Throw away everything we don't need anymore to free up memory*/
   BN_CTX_free(ctx);

   return result;
}

/*
 * This is a helper function to encrypt a given message using the RSA algorithm
 * We calculate the chipertext to be message^modulo mod public_key this comes from
 * the RSA algorithm specifying that the chiper text is congruent to the aforementioned
 * equation.
 *
 * @params: message -> the message you want to encrypt represented as a BIGNUM
 * @params: modulo -> the mod you are using for the encryption
 * @params: public_key -> the public key being used for the encryption
 * @return: The ciphertext resulting from the encryption
 */
BIGNUM* encryptUsingRSA(BIGNUM* message, BIGNUM* modulo, BIGNUM* public_key)
{
   /* As before we need to make a CTX structure */
   BN_CTX *ctx = BN_CTX_new();
   BIGNUM* result = BN_new();
   /* Do the actual encryption */
   BN_mod_exp(result, message, modulo, public_key, ctx);
   /*Throw away everything we don't need anymore to free up memory */
   BN_CTX_free(ctx);

   return result;
}

/*
 * This is a helper funtion to decrypt a given message using the RSA algorithm
 * We calculate the plaintext to be (message^modulo)^public_key which comes from the RSA
 * algorithm specifying that the plaintext is congruent to the aforementioned equation.
 *
 * @params: e_message -> the encrypted message as a hexadecmial number
 * @params: private_key -> the users private key
 * @params: public_key -> the public key forthe message
 */
 BIGNUM* decryptUsingRSA(BIGNUM* e_message, BIGNUM* private_key, BIGNUM* public_key)
 {
      /* As before we need to make a CTX structure */
      BN_CTX *ctx = BN_CTX_new();
      BIGNUM* result = BN_new();
      /* Do the actual decryption */
      BN_mod_exp(result, e_message, private_key, public_key, ctx);
      /*Throw away everything we don't need anymore to free up memory */
      BN_CTX_free(ctx);

      return result;
 }
/* END TASK HELPER FUNCTIONS */

/* TASK FUNCTIONS FOR EACH TASK IN THE LAB */

/*
 * The below funtions run each of the tasks for the lab listed as
 * 1. Deriving the Private Key
 * 2. Encrypting a Message
 * 3. Decrypting a Message
 * 4. Signing a Message
 * 5. Verifying a Signature
 * 6. Manually Verifying a Signature
 * Each one of these functions is called within main()
 */
 void task1()
 {
    /* Make some BIGNUMs for our large prime numbers */
    BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();
    BIGNUM* e = BN_new();

    /* Assign the values given in the lab description */
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");

    /*Find the private key and print it out to the console*/
    BIGNUM* private_key = getRSAPrivateKey(p, q, e);
    printBN("Private Key: ", private_key);
 }

 void task2()
 {
    /* Setup the keys and modulo*/
    BIGNUM* private_key = BN_new();
    BIGNUM* public_key = BN_new();
    BIGNUM* modulo = BN_new();
    BN_hex2bn(&private_key, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_hex2bn(&public_key, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&modulo, "010001");

    /* Setup the message, we used python to convert the message to hex using the following
     * python -c ’print("A top secret!".encode("hex"))’ and it returned:
     * 4120746f702073656372657421
     */
     BIGNUM* message = BN_new();
     BN_hex2bn(&message, "4120746f702073656372657421");

     /* Let's encrypt */
     BIGNUM* encrypted_message = BN_new();
     BIGNUM* check_result = BN_new();
     encrypted_message = encryptUsingRSA(message, modulo, public_key);
     printBN("The encrypted message is: ", encrypted_message);
     /* Let's check our result by decrypting */
     check_result = decryptUsingRSA(encrypted_message, private_key, public_key);
     printBN("The decrypted hex value is: ", check_result);
     printf("%s\n","The decrypted value should match: 4120746f702073656372657421");
 }

 void task3()
 {
    /* Setup the message to be decrypted */
    BIGNUM* encrypted_message = BN_new();
    BN_hex2bn(&encrypted_message, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");

    /* Setup the keys - same keys as from Task 2 */
    BIGNUM* private_key = BN_new();
    BIGNUM* public_key = BN_new();
    BN_hex2bn(&private_key, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_hex2bn(&public_key, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");

    /* Let's decrypt */
    BIGNUM* decrypted_message = BN_new();
    decrypted_message = decryptUsingRSA(encrypted_message, private_key, public_key);

    /* Use our utility function to print it out in ASCII */
    printf("%s", "Decrypted message is: " );
    printHX(BN_bn2hex(decrypted_message));
    printf("\n");
 }

 void task4()
 {
    /* Setup the message to sign
     * Again we use python to turn the text "I own you $2000." into hex
     * python -c 'print("I owe you $2000.".encode("hex"))' is the command to run
     */
    BIGNUM* message_to_sign = BN_new();
    BN_hex2bn(&message_to_sign, "49206f776520796f752024323030302e");

    /* Setup the keys - same keys as from Task 2 */
    BIGNUM* private_key = BN_new();
    BIGNUM* public_key = BN_new();
    BN_hex2bn(&private_key, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_hex2bn(&public_key, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");

    /* Now we just need to encrypt the message */
    BIGNUM* signature = BN_new();
    signature = encryptUsingRSA(signature, private_key, public_key);
    printBN("Signature for I owe you $2000. is: ", signature);

    /* Change the message slightly to see what happens */
    /* python -c 'print("I owe you $3000.".encode("hex"))' is the command to run */
    BIGNUM* message_to_sign2 = BN_new();
    BN_hex2bn(&message_to_sign2, "49206f776520796f752024333030302e")

    /*As before we encrypt the message as a signature */
    BIGNUM* signature2 = BN_new();
    signature2 = encryptUsingRSA(signature2, private_key, public_key);
    printBN("Signature for I owe you $3000. is: ", signature2);
 }

 void task5()
 {

 }

 void task6()
 {

 }
/* END TASK HELPER FUNCTIONS */

int main()
{
   printf("%s\n", "Task 1 - Deriving the Private Key");
   task1();
   printf("%s\n", "Task 2 - Encrypting a Message");
   task2();
   printf("%s\n", "Task 3 - Decrypting a Message");
   task3();
   printf("%s\n", "Task 4 - Signing a Message");
   task4();
   printf("%s\n", "Task 5 - Verifying a Signature");
   //task5();
   printf("%s\n", "Task 6 - Manually Verifying an X509 Certificate");
   //task6();

   return 1;
}
