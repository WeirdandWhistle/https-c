#include <unistd.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <math.h>

struct TLSPlaintext{
	unsigned char type;
	uint16_t legacy_record_version; // alwasys 0x0303
	uint16_t length;	
};

struct clientHello {
	uint16_t legacy_version; // alwasys 0x0303
	unsigned char random[32];
	unsigned char legacy_session_id[32];
	unsigned char *cipher_suites; // 2^16 - 1
	unsigned char legacy_compression_methods[255]; // 2^8 -1
	//extensions...
};
void getUint16(int fd, uint16_t *out){
	unsigned char buf[2];
	read(fd, &buf, 2);
	*out = ((buf[0] << 8*(2-1)) | (buf[1] << 8*(2-2)));
//	printf("from func: %x\n",*out);
}

int main(){

	if(sodium_init() < 0){
		printf("sodium lib could not be init\n");
		return 1;
	}else{
		printf("sodium succefuly init\n");
	}

	unsigned char out[crypto_hash_sha256_BYTES];
	unsigned char in[] = "1234";

	int from = crypto_hash_sha256(out,in,4);
	printf("hash of %s\n",in);
	for(int i = 0; i<crypto_hash_sha256_BYTES; i++){
		printf("%02X",out[i]);
	}
	printf("\n");

	int soc = socket(AF_INET, SOCK_STREAM, 0);

	int opt = 1;
	setsockopt(soc, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	
	struct sockaddr_in my_addr;
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(2000);
	my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	int binded = bind(soc, (struct sockaddr *)&my_addr, sizeof(my_addr));
	if(binded<0){printf("bind error!"); return 1;}

	listen(soc, 1);

	struct sockaddr accept_addr;
	socklen_t addrlen = sizeof(accept_addr);

	printf("setup socket on port 2000 and ready read on acc\n");

	int acc = accept(soc, &accept_addr, &addrlen);
	if(acc<0){printf("accept error!"); return 1;}


	struct clientHello ch = {0};
	struct TLSPlaintext record = {0};

	unsigned char lengthBuffer[2];

	read(acc, &record.type, 1);
	getUint16(acc, &record.legacy_record_version);
	getUint16(acc, &record.length);
	
	printf("type %u\n",record.type);
	printf("legacay version: %x\n",record.legacy_record_version);
	printf("length: %x\n", record.length);




	return 0;
}
