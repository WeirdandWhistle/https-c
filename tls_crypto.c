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
