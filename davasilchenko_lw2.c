#include <stdio.h>
#include <string.h>

#include <libakrypt.h>

int read_write_file(const char* filename, ak_uint8** buf, size_t* len, int rw) {
	int nRet = 0;
	FILE* file;
	if (rw == 0) {
		file = fopen(filename, "rb");
		if (!file) {
			nRet = -1;
		}
		else {
			fseek(file, 0, SEEK_END);
			*len = ftell(file);
			rewind(file);

			*buf = malloc(*len);

			if (fread(*buf, 1, *len, file) < *len) {
				free(*buf);
				nRet = -1;
			}
			fclose(file);
		}
	}
	else {
		file = fopen(filename, "wb");
		if (!file) {
			nRet = -1;
		}
		else {
			if (fwrite(*buf, 1, *len, file) < *len) {
				nRet = -1;
			}
			fclose(file);
		}
	}
	return 0;
}

int encrypt_decrypt(const char* input_file, const char* output_file, int has_password, ak_uint8* password) {
	ak_uint8* buf;
	
	struct bckey ctx;

	int nRet = 0;
	size_t len = 0;
	
	read_write_file(input_file, &buf, &len, 0);

	ak_bckey_create_magma(&ctx);

	if (has_password) {
		ak_bckey_set_key_from_password(
			&ctx,
			password,
			strlen(password),
			"sticky_salt",
			strlen("sticky_salt")
		);
	}
	else {
		struct random generator;
		ak_random_create_nlfsr(&generator);
	
		ak_bckey_set_key_random(&ctx, &generator);
	
		ak_random_destroy(&generator);
	}

	if (ak_bckey_ofb(&ctx, buf, buf, len, NULL, 8) != ak_error_ok) {
		nRet = -1;
	}
	else {
		nRet = read_write_file(output_file, &buf, &len, 1);
	}

	ak_bckey_destroy(&ctx);

	return nRet;
}


int main(int argc, char* argv[]) {
	const char *input, *output;
	ak_uint8* password;
	int has_password = 0;
	int nRet = 0;

	if (ak_libakrypt_create(NULL) != ak_true) {
		ak_libakrypt_destroy();
		return EXIT_FAILURE;
	}

	for (int i = 1; i < argc; ) {
		if (strcmp(argv[i], "--key") == 0) {
			has_password = 1;
			password = argv[i+1];
		}
		else {
			input = argv[i];
			output = argv[i+1];
		}
		i += 2;
	}
	if (
			(input == NULL) ||
			(output == NULL) ||
			(strlen(input) * strlen(output) == 0)
	) {
		fprintf(stderr, "No input / output file...\n");
		nRet = -1;
	}
	else {
		nRet = encrypt_decrypt(input, output, has_password, password);
	}

	ak_libakrypt_destroy();

	if (nRet) {
		return EXIT_FAILURE;
	}
	else {
		return EXIT_SUCCESS;
	}
}
