#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <math.h>
#include <ctype.h>
#include "tls_crypto.h"

void HKDF_Expand_Label(unsigned char *outPtr, unsigned char *Secret, unsigned char *Label, uint8_t label_length, unsigned char *Contex, uint8_t contex_length, uint16_t Length){
	unsigned char expandLabel[6+label_length];
	unsigned char tls13[] = {'t','l','s','1','3',' '};
	//compinde Lable and tls13
	for(int i = 0; i<sizeof(expandLabel);i++){
		if(i>=6){expandLabel[i] = Label[i-6];}
		else{expandLabel[i] = tls13[i];}
	}

	unsigned char l[2+1+sizeof(expandLabel)+1+contex_length];

	uint16_t c = 0;

	uint16_t nol = htons(Length);

	l[c] =  (nol>>0)&0xFF; l[c+1] = (nol>>8)&0xFF; c+=2;
	l[c] = (uint8_t) (6+label_length) & 0xFF; c++;
	for(int i = 0; i<sizeof(expandLabel);i++){
		l[i+c] = expandLabel[i];
	} c += sizeof(expandLabel);

	l[c] = (contex_length) & 0xFF; c++;
	for(int i = 0; i<contex_length;i++){
		l[c+i] = Contex[i];
	} c+= contex_length;

	crypto_kdf_hkdf_sha256_expand(outPtr, Length, l, sizeof(l), Secret);
}

int create_record(unsigned char *outPtr, unsigned long long *out_len, unsigned char *message, unsigned long long mlen, unsigned char type, int padding_length, unsigned char *k, unsigned char *nouce){
	
	if(mlen + 1 + padding_length + crypto_aead_chacha20poly1305_IETF_ABYTES > pow(2,14)){
		return 1;
	}
	uint16_t record_length = mlen + 1 + padding_length + crypto_aead_chacha20poly1305_IETF_ABYTES;
	uint16_t big_edian = htons(record_length);

	unsigned char ad[] = {23, 0x03, 0x03, (big_edian)&0xFF,(big_edian>>8)&0xFF};

	unsigned char *cipher = malloc(record_length);
	unsigned long long clen;

	unsigned char *plaintext = malloc(mlen + 1 + padding_length);

	unsigned char *iter = plaintext;

	memcpy(iter, message, mlen);
	iter += mlen;

	*iter = type; iter += 1;

	for(int i = 0; i < padding_length;i++){
		*iter = 0;
		iter += 1;
	}

	crypto_aead_chacha20poly1305_ietf_encrypt(cipher, &clen,
							plaintext, mlen + 1 + padding_length,
							ad, sizeof(ad),
							NULL, nouce, k);

	iter = outPtr;

	memcpy(iter, ad, sizeof(ad));
	iter += sizeof(ad);

	memcpy(iter, cipher, clen);	

	free(cipher);
	free(plaintext);

	return 0;
}

void create_record_length(int *length, int mes_len, int padding_len){
	*length = 1 + 2 + 2 + mes_len + 1 + padding_len + crypto_aead_chacha20poly1305_IETF_ABYTES;
}

int get_record_socket(unsigned char *outPtr, unsigned long long *out_len, int fd, unsigned char *nouce, unsigned char *k){
	unsigned char type;
	unsigned char legacy_version[2];
	unsigned char length[2];
	uint16_t len;

	read(fd, &type, 1);
	read(fd, legacy_version, 2);
	read(fd, length, 2);

	len = (length[0] << 8) | (length[1]);
	if(len > pow(2,14)){
		printf("too much record!\n");
		return 1;
	}

	unsigned char *buffer = malloc(len);

	int read_on_wire = read(fd, buffer, len);
	if(read_on_wire == -1){
		printf("read(); failed!\n");
		return 1;
	} else if(read_on_wire != len){
		printf("HEARTBLEED atempt! read(%d) != length field(&d)\n", read_on_wire, len);
		return 1;
	}

	unsigned char ad[] = {type, legacy_version[0], legacy_version[1], length[0], length[1]};

	outPtr = malloc(len);

	int decryption = crypto_aead_chacha20poly1305_ietf_decrypt(outPtr, out_len,
									NULL,
									buffer, len,
									ad, sizeof(ad),
									nouce, k);

		
	free(buffer);
	return decryption;
}
