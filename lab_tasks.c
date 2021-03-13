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
    signature = encryptUsingRSA(message_to_sign, private_key, public_key);
    printBN("Signature for I owe you $2000. is: ", signature);

    /* Change the message slightly to see what happens */
    /* python -c 'print("I owe you $3000.".encode("hex"))' is the command to run */
    BIGNUM* message_to_sign2 = BN_new();
    BN_hex2bn(&message_to_sign2, "49206f776520796f752024333030302e");

    /*As before we encrypt the message as a signature */
    BIGNUM* signature2 = BN_new();
    signature2 = encryptUsingRSA(message_to_sign2, private_key, public_key);
    printBN("Signature for I owe you $3000. is: ", signature2);
 }

 void task5()
 {
    /* To verify the signature we need to decrypt it using the public key */
    /* Setup the signature, keys, and modulo */
    BIGNUM* signature_to_verify = BN_new();
    BIGNUM* public_key = BN_new();
    BIGNUM* message = BN_new();
    BIGNUM* modulo = BN_new();
    BN_hex2bn(&signature_to_verify, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
    BN_hex2bn(&public_key, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    BN_hex2bn(&message, "4c61756e63682061206d697373696c652e");
    BN_hex2bn(&modulo, "010001");

    /* Let's decrypt and verify the signature */
    BIGNUM* check_result = BN_new();
    check_result = decryptUsingRSA(signature_to_verify, modulo, public_key);
    printf("%s", "The message is: ");
    printHX(BN_bn2hex(check_result));
    printf("\n");

    /* Let's corrupt the signature by changing the last byte to 3F */
    printf("%s\n","--- Corrupted signature ---" );
    BN_hex2bn(&signature_to_verify, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
    check_result = decryptUsingRSA(signature_to_verify, modulo, public_key);
    printf("%s", "The message from the corrupted signature is: " );
    printHX(BN_bn2hex(check_result));
    printf("\n");
 }

 void task6()
 {
    /* setup the public key and modulus for the certificate */
    /* The example site being used is apple.com */
    BIGNUM* public_key = BN_new();
    BIGNUM* modulo = BN_new();
    BN_hex2bn(&public_key, "ACE894257B536C98682E3C9DABE603176CAE72164808824498C4FA3DBE02621C8F75CDC6D8564AED5CB6ADE2CC672218461052C78E14CB01C7C315F5D3BB997A265A8E54F1B4EA30A055DB75D6D2424E378137839E6BF0E7CE353C956CF2DE047604FB1C7B92ABE3887225277A4D3811278CC09D5F34E750C34FBC031187C2FC1359435CF1CA33DB3FEA6A0CDE0B2EE0D173F8C3E6A3A8A4B70C4BD738494D4EF7B7DAE9ACC26E9791F26419741B3FDF76B55FF419AED517178CA468BD0BACC56DA91FA0B4F0C3383CB116E3CAA8156359085337A5B0D066E0BB173D9BA4327DFB22B3459131336A2248048D535D186E018D9BAEF1524C118F679B9E65EB06CB");
    BN_hex2bn(&modulo, "10001");

    /* Setup the signature */
    BIGNUM* signature = BN_new();
    BN_hex2bn(&signature, "22c083a8416468dcda6def0746323257259efe5d434bf217c25f1e86e4ac543b3be996df92e20d8fd9205f4a04b198e5e3ad1d2617f3e2adb756dc462970abd5638a9f3402d6f85a9ceaf6d33acc5c7ea31546bf562c3967428abf78f37f2d3f477420baa8caa51656ee87832241bb764400169265c231e138c9f4b84eb73c8ee3899c1ea80d5e203b21d2b74cfb37f62026571dfedcf426c236c61a32a0474ace448194b826ba615a91d1a775c161b8336e0781347ff9de340b824d558dc5169b54bc20b0e320f927393676e16c0260bd6d9c694dbcdc868390216dc212df2152aba2a8106f3affbb608dc9acc1c1b0bb7d4f8e18622282f979059e1ef21bd1");

    /* We also got the hash of the signature so once we decrypt the signature
     * we can use this hash to verify that the signature is valid
     */
     BIGNUM* signature_decrypted = BN_new();
     signature_decrypted = decryptUsingRSA(signature, modulo, public_key);

     int masked = BN_mask_bits(signature_decrypted, 256);
      printBN("Hash is: ", signature_decrypted);
      printf("%s\n", "Compare to: eb1acf5b32775f0114adb8a14ff6ddf361e60b15fbde9e1407bb08f6caeb2be2");

  }
/* END TASK HELPER FUNCTIONS */

int main()
{
   printf("%s\n", "Task 1 - Deriving the Private Key");
   task1();
   printf("\n");
   printf("%s\n", "Task 2 - Encrypting a Message");
   task2();
   printf("\n");
   printf("%s\n", "Task 3 - Decrypting a Message");
   task3();
   printf("\n");
   printf("%s\n", "Task 4 - Signing a Message");
   task4();
   printf("\n");
   printf("%s\n", "Task 5 - Verifying a Signature");
   task5();
   printf("\n");
   printf("%s\n", "Task 6 - Manually Verifying an X509 Certificate");
   task6();

   return 1;
}
