#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <openssl/conf.h>
#include <openssl/kdf.h>
//#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#define DSTCONNID_LEN	8
#define HASH_SHA2_256_LENGTH            32

const unsigned char _dstconnid[] = "05E0DC1FEB30D22B";
static const uint8_t hanshake_salt_draft_q50[20] = {
	0x50, 0x45, 0x74, 0xEF, 0xD0, 0x66, 0xFE, 0x2F, 0x9D, 0x94,
	0x5C, 0xFC, 0xDB, 0xD3, 0xA7, 0xF0, 0xD3, 0xB5, 0x6B, 0x45
};

//GCRY_MD_SHA256

void handleErrors() {
	ERR_print_errors_fp(stderr);
	abort();
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

int HKDF_Extract(const unsigned char *salt, const size_t salt_len, const unsigned char *key, const size_t key_len, unsigned char *hash, size_t hash_len) {
	EVP_PKEY_CTX 	*pctx;
	int		mode = EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY;

	debug_print_rawfield(salt, 0, salt_len);
	debug_print_rawfield(key, 0, key_len);

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

	if (EVP_PKEY_derive_init(pctx) <= 0) {
		printf("Error init\n");
		handleErrors();
	}
	
	if (EVP_PKEY_CTX_hkdf_mode(pctx, mode) <= 0) {
		printf("Error set_hkdf_mode\n");
		handleErrors();
	}

	if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
		printf("Error set_hkdf_md\n");
		handleErrors();
	}

	if (EVP_PKEY_CTX_set1_hkdf_key(pctx, key, key_len) <= 0) {
		printf("Error set1_hkdf_key\n");
		handleErrors();
	}

	if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0) {
		printf("Error set1_hkdf_salt\n");
		handleErrors();
	}

/*
	unsigned char label[] = "tls13 client in";
	if (EVP_PKEY_CTX_add1_hkdf_info(pctx, label, strlen(label)) <= 0) {
		handleErrors();
	}
*/
	size_t len = hash_len;
	if (EVP_PKEY_derive(pctx, hash, &len) <= 0) {
		printf("Error deriving key\n");
		handleErrors();
	}
	return len;
}

int HKDF_Expand(const unsigned char *key, const size_t key_len, const unsigned char *label, const size_t label_len, unsigned char *hash, size_t hash_len) {
	EVP_PKEY_CTX 	*pctx;
	int		mode = EVP_PKEY_HKDEF_MODE_EXPAND_ONLY;

	printf("LABEL LEN %d ", label_len);
	debug_print_rawfield(label, 0, label_len);

	printf("KEY LEN %d ", key_len);
	debug_print_rawfield(key, 0, key_len);

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

	if (EVP_PKEY_derive_init(pctx) <= 0) {
		printf("Error init\n");
		handleErrors();
	}
	
	if (EVP_PKEY_CTX_hkdf_mode(pctx, mode) <= 0) {
		printf("Error set_hkdf_mode\n");
		handleErrors();
	}

	if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
		printf("Error set_hkdf_md\n");
		handleErrors();
	}

	if (EVP_PKEY_CTX_set1_hkdf_key(pctx, key, key_len) <= 0) {
		printf("Error set1_hkdf_key\n");
		handleErrors();
	}

	if (EVP_PKEY_CTX_add1_hkdf_info(pctx, label, label_len) <= 0) {
		handleErrors();
	}

	size_t len = hash_len;
	if (EVP_PKEY_derive(pctx, hash, &len) <= 0) {
		printf("Error deriving key\n");
		handleErrors();
	}


	return len;
}

 #include <arpa/inet.h>

int create_tls13_label(const unsigned int a, const unsigned char *label, unsigned char *out, size_t out_len) {
	unsigned char	pref_label[] 	= "tls13 ";
	size_t		pref_label_len 	= strlen(pref_label);
	size_t 		label_len    	= strlen(label);
	size_t 		v_label_len 	= pref_label_len + label_len;
	size_t		len		= 0;
	const uint16_t 	length 		= htons(a);

	memcpy(&out[len], &length, sizeof(length));
        len += sizeof(length);	

        memcpy(&out[len], &v_label_len, 1);
	len +=1;

        memcpy(&out[len], pref_label, pref_label_len);
        len += pref_label_len;

        memcpy(&out[len], label, label_len);
        len += label_len;

	unsigned int context_length = 0;
	memcpy(&out[len], &context_length, 1);
	len += 1;
	return len;
}

int main(int argc, char* argv[])
{
	unsigned char	dstconnid[DSTCONNID_LEN] = { 0 } ;
	unsigned char 	out[HASH_SHA2_256_LENGTH] = { 0 };
	size_t 		outlen = HASH_SHA2_256_LENGTH;
	unsigned char 	pkm[HASH_SHA2_256_LENGTH] = { 0 };
	size_t 		pkmlen = HASH_SHA2_256_LENGTH;

	unsigned char 	secret[HASH_SHA2_256_LENGTH] = { 0 };
	size_t 		slen = HASH_SHA2_256_LENGTH;

	unsigned char   label[32] = { 0 };
	size_t		label_len = 0;


	label_len = create_tls13_label(32, "client in", label, sizeof(label));

	convert_char_to_byte(_dstconnid, dstconnid, DSTCONNID_LEN);
	int len	= HKDF_Extract(hanshake_salt_draft_q50, 20, dstconnid, DSTCONNID_LEN, pkm, pkmlen);

	printf("expected:\n29BE8C3445CA4E73AAE8017FF86D0F4E51DF2229853A50E387618DB3BD20FAAD\n");
	debug_print_rawfield(pkm, 0, len);

	printf("LABEL LEN %d\n", label_len);
	int len2 = HKDF_Expand(pkm, pkmlen, label, label_len, secret, slen);
	printf("expected:\n6E31A620096888A886ED8023915B02B78DE4CD8DEBEC31B3D47F822EECFB1C19\n");
	debug_print_rawfield(out, 0, len2);
	printf("TRYING TO OUTPUT:\n");

	outlen = 16;
	label_len = create_tls13_label(outlen, "quic key", label, sizeof(label));
	printf("LABEL LEN %d\n", label_len);
	len2 = HKDF_Expand(secret, slen, label, label_len, out, outlen);
	printf("expected:\n3C239B1C4A98D7DB260B292196B85E9D\n");
	debug_print_rawfield(out, 0, len2);

	outlen = 12;
	label_len = create_tls13_label(outlen, "quic iv", label, sizeof(label));
	printf("LABEL LEN %d\n", label_len);
	len2 = HKDF_Expand(secret, slen, label, label_len, out, outlen);
	printf("expected:\n348AC0C4A59F5B20BD460DEB\n");
	debug_print_rawfield(out, 0, len2);

	outlen = 16;
	label_len = create_tls13_label(outlen, "quic hp", label, sizeof(label));
	printf("LABEL LEN %d\n", label_len);
	len2 = HKDF_Expand(secret, slen, label, label_len, out, outlen);
	printf("expected:\nAC8D192E1924E37ACB5B63011AE4E812\n");
	debug_print_rawfield(out, 0, len2);

	return 0;
}
