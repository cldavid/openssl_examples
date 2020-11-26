#include <stdio.h>
#include <inttypes.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>


#define KEY_LENGTH 	16
#define TEXT_LENGTH 	16
#define IV_LENGTH	12
#define ATAG_LENGTH	16
#define SECRET_LENGTH	1315
#define PPKEY_LENGTH	32
#define AAD_LENGTH	19

const unsigned char _key[] 		= "AC8D192E1924E37ACB5B63011AE4E812";
const unsigned char _ppkey[]		= "3C239B1C4A98D7DB260B292196B85E9D0036B124EC7F00000000000000000000";	
const unsigned char _plaintext[] 	= "5F0F15642E6C448850344066E7ADFEA7";
const unsigned char _test_string[] 	= "1FBF2347D3B0E828EC52483D405FC345";
const unsigned char _aad[]		= "C0513035300805E0DC1FEB30D22B0000453401";
const unsigned char _iv[]		= "348AC0C4A59F5B20BD460DEA";
const unsigned char _atag[]		= "D591388E7A114C7F012FEB14F0EADDD3";
const unsigned char _secret[] = 	"5A0AA85F0F15642E6C448850344066E7ADFEA795EA1B78A14EB4D0C2AD8E44B20C4EF3ACC30D1727A51ADC81300027DD7726B31D14DA5ADB68703A8CDF11011C920D1B2204F1DEE7E18186B6500C327612DD1FB23878C59E91C07069F858D100E7EC1F39BC246C65F51D1A4FDAF7DC15177A359C66CA98361DD71000F75E178A5DCBD0B6B24A249DA00646E48EBD286350E43AC962FBD8668D457F9C9E52F1454F214E0EDF48D3F6563D2C9C22BA1179B13FDC0FFBFD4859801EBEE32EDEB6FF88F7E555D736AA8303CEB9608338F858094748073C1DF4E905D4E874DE638DA00F83EB5990565D36BAC8DE57FCE64D6F8924BAD6D07E451B9A028F1C61430A95A0FBDF259ADB9600447CB31C21DF794DF478E6F9B11AB43B6D341BA4E1BFA1DDB0855A9CB48EC85F269CE88919AA729F0F687A937E590D1190C7BE41C1B1CA9975F3B9CC2C2D9530F8E0367FD4A4AA27D4E44936053E5A0BF7343444EFAB50D4F9DA91227D8E11FFAF5534586EFF4B4EF0055E039AF26038D2B6C7561D4D305BF362A07F6425767E0E00845E7FB9950188480372412EDA0A7EE58CEF22D4A4457A352D6601E3D5E8FAF5A65C6D2C1E1CF581E9AC0AA9D02A9C402BE1C06B32C5741034FC915FE1B1B21061ECD49AC4B03B18D5E3C64CA2A0D99B1EB5B400C941F1AF05FB14358651670E8E17CFF84EB0CA625765D2F7B497FC674357C3B1F3A73C7E03C9D6907F72EE55846A3715F8CFAAD8E60AD8C566B05BF373E70491396A1A050E2D140AF0E2EAB3420667D13BCE8B88EC9A50148625425133986A0C96AD775F24D393F8C0D464B965927DBB424713265211F2F842754F0A72453E51B6B074AA15BFB3E68D7046EC287AF2D8C07E28786755922CB7AA559A0A6C19CAC6860731B040C17135217CE270CBE266D2DA968625B23FE39EF9264C4410CCE471C176571E40AB98F2583B4F78704B459733CC0A1CF006386CD5201616AF12223588BA390A28680E15C6E0FCE34C67D3F14A8D7FDFC3471D30F9B7E791965E89B749A7DC7F3DE0C314BB4A469BD7B59761B45377E35AB1C3EC23B16CB46197EC4966661303644E541A6E4550728444560D6AD3BAA7A080FCA08D4E4D365DD7ADBA8C1645010E31865C47196EFD13FDE061022F8CA86EED8E2E8ED568C5E4331DF9D0AAC31ECAD37D21777EA1B8DBB0D4F295A6F882BA53E80654B498D919376DDE0F13EFC58688430C4D1FEB991EE84B2273293FC137C74F6E4D94D20DCE20AC8CF471687A68310E4BC7409521D9446684A9FF33C8D5527E54F604B906BF59F046754CAC7733C7479241F1F3F3DD4BFAE59A155563B1B36AEEE17C3D2CAB06A906A07B23EFB64DCE72B2FA1E8F18BE6D236843AC585B6D6974BBD35707CFC60F1AA7B19F84F1520CAE4B3CBE2C5C38CCE674EE49E2D299D3ED407B9452D2292B4E726DE470F91C4BBD53B261636974C3867E1E9A509F2869F3890E5DC5FFE2F0CEFBC534D5E0A7B9D384F16F29DEE67EA4FBAA5652C1BB4FFEE4A80D7061EB1FA2ED1A93B5F7FBEDC5AC04B2F45D01696750A66B641020FE4B03C123DA577CE750C29B40F1BDEA2430826EF1EA7CAF35A7C147B63A8F0ADCA8ABAE6E2926DE352E262DB9826642BE4DA3781F98F1F4F2D0E11651FF8FA9BC88096988EFE204D0890A9263598B694643C8A2DF2B1E39940F79D4B4AEF6C790034B7E880747E834EB7ADB385FD1CB1C07B8AC471DE2E8EE83176D7B946175DC43E0C053441880ED94A1982C2A461F593FDEC25D2CF82DE879B2580120C03D37AA2E37344013371A2B6B181B1B132E526B6FF3F6C757C14B6AEB3BCAF65AF9DD9AD093BE0D1DCA6564305D965E";



void handleErrors() {
	ERR_print_errors_fp(stderr);
	abort();
}




/* GCM AES ENCRYPTION */
int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
		unsigned char *aad, int aad_len,
		unsigned char *key,
		unsigned char *iv, int iv_len,
		unsigned char *ciphertext,
		unsigned char *tag)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;


	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	/* Initialise the encryption operation. */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		handleErrors();

	/*
	 * Set IV length if default 12 bytes (96 bits) is not appropriate
	 */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
		handleErrors();

	/* Initialise key and IV */
	if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
		handleErrors();

	/*
	 * Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
		handleErrors();

	/*
	 * Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;

	/*
	 * Finalise the encryption. Normally ciphertext bytes may be written at
	 * this stage, but this does not occur in GCM mode
	 */
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		handleErrors();
	ciphertext_len += len;

	/* Get the tag */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
		handleErrors();

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
		unsigned char *aad, int aad_len,
		unsigned char *tag,
		unsigned char *key,
		unsigned char *iv, int iv_len,
		unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	int ret;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	/* Initialise the decryption operation. */
	if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
		handleErrors();

	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
		handleErrors();

	/* Initialise key and IV */
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
		handleErrors();

	/*
	 * Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
		handleErrors();

	/*
	 * Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	printf("DEBUG LEN %d\n", len);
	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
		handleErrors();

	/*
	 * Finalise the decryption. A positive return value indicates success,
	 * anything else is a failure - the plaintext is not trustworthy.
	 */
	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	if(ret > 0) {
		/* Success */
		plaintext_len += len;
		return plaintext_len;
	} else {
		/* Verify failed */
		return -1;
	}
}



int encrypt(unsigned char *plaintext, int plaintext_len, const EVP_CIPHER *type, unsigned char *key,
		unsigned char *iv, unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	/*
	 * Initialise the encryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits
	 */
	if(1 != EVP_EncryptInit_ex(ctx, type, NULL, key, iv))
		handleErrors();

	/*
	 * Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;

	/*
	 * Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		handleErrors();
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, const EVP_CIPHER *type, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, type, NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int convert_char_to_byte(const unsigned char *text_arr, unsigned char *byte_arr, size_t len) {
	unsigned char buf[3] = { 0 };
	printf("%s\n", text_arr);
	for (size_t i = 0; i < len; i++) {
		buf[0] = text_arr[i * 2];
		buf[1] = text_arr[(i * 2) + 1];
		buf[2] = '\0';
		byte_arr[i] = strtoimax(buf, NULL, 16);
		printf("%02X", byte_arr[i]);
	}
	printf("\n");
}

void debug_print_rawfield(const unsigned char *app_data, size_t start_offset, size_t len) {
        size_t i;

        for (i = 0; i < len; i++) {
                printf("%02X", app_data[start_offset + i]);
        }
        printf("\n");
}

int main(int argc, char *argv[], char *envp[]) {
	unsigned char ppkey[PPKEY_LENGTH] 	= { 0 };
	unsigned char key[KEY_LENGTH] 		= { 0 };
	unsigned char plaintext[KEY_LENGTH] 	= { 0 };
	unsigned char ciphertext[1024]		= { 0 };
	unsigned char cleartext[1024]		= { 0 };
	unsigned char test_string[1024]		= { 0 };
	unsigned char aad[AAD_LENGTH]		= { 0 };
	unsigned char iv[IV_LENGTH]		= { 0 };
	unsigned char atag[ATAG_LENGTH]		= { 0 };
	unsigned char secret[SECRET_LENGTH]	= { 0 };
	unsigned char decoded_msg[10 * 1024]	= { 0 };

	char buf[3];
	
	const EVP_CIPHER *type = EVP_aes_128_ecb();

	printf("KEY LEN %u\n", strlen(_key));
	convert_char_to_byte(_key, key, KEY_LENGTH);

	printf("TEXT LEN %u\n", strlen(_plaintext));
	convert_char_to_byte(_plaintext, plaintext, KEY_LENGTH);


	int test_len = strlen(_test_string) / 2;
	printf("TEST LEN %u\n", test_len);
	convert_char_to_byte(_test_string, test_string, test_len);

	int res = encrypt(plaintext, 16, type, key, NULL, ciphertext);
	printf("ENCRYPTED TEXT RES: %d\n", res);
	debug_print_rawfield(ciphertext, 0, res);

        BIO_dump_fp(stdout, (const char *)ciphertext, res);


	int res2 = decrypt(ciphertext, res, type, key, NULL, cleartext);
	printf("DECRYPTED TEXT RES: %d\n", res2);
        BIO_dump_fp(stdout, (const char *)cleartext, res2);

	if (0 != memcmp(ciphertext, test_string, test_len)) {
		printf("Error cipher text is not equal to test string\n");
		return 0;
	} else {
		printf("Test was successfull\n\n\n");
	}
	printf("SECRET LEN %u\n", strlen(_secret));
	convert_char_to_byte(_secret, secret, SECRET_LENGTH);

	printf("PPKEY LEN %u\n", strlen(_ppkey));
	convert_char_to_byte(_ppkey, ppkey, PPKEY_LENGTH);

	printf("AAD LEN %u\n", strlen(_aad));
	convert_char_to_byte(_aad, aad, AAD_LENGTH);


	printf("IV LEN %u\n", strlen(_iv));
	convert_char_to_byte(_iv, iv, IV_LENGTH);

	printf("ATAG LEN %u\n", strlen(_atag));
	convert_char_to_byte(_atag, atag, ATAG_LENGTH);

	memset(plaintext, 0, sizeof(plaintext));
	int res3 = gcm_decrypt(secret, SECRET_LENGTH, aad, AAD_LENGTH, atag, ppkey, iv, IV_LENGTH, decoded_msg);

	printf("PLAINTEXT RES: %d\n", res3);
        BIO_dump_fp(stdout, (const char *)decoded_msg, res3);


	return 1;
}
