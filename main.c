#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>

int main(){

	if(sodium_init() < 0){
		printf("sodium lib could not be init\n");
		return 1;
	}else{
		printf("sodium succefuly init\n");
	}

	unsigned char out[crypto_hash_sha256_BYTES];
	unsigned char in[] = {1,2,3,4};

	int from = crypto_hash_sha256(out,in,sizeof(in));

	for(int i = 0; i<crypto_hash_sha256_BYTES; i++){
		printf("%02X",out[i]);
	}

	return 0;
}
