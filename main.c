#include <string.h>
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
struct Handshake {
	unsigned char msg_type;
	uint32_t length; 
};
struct Extension {
	uint16_t extension_type;
	uint16_t extension_data_length;
	unsigned char *extension_data;
};

struct ClientHello {
	uint16_t legacy_version; // alwasys 0x0303
	unsigned char random[32];
	uint8_t legacy_session_id_length;
	unsigned char legacy_session_id[32];
	uint16_t cipher_suites_length;
	unsigned char *cipher_suites; // 2^16 - 1
	uint8_t legacy_compression_methods_length;
	unsigned char legacy_compression_methods[255]; // 2^8 -1
	uint16_t extensions_length;
	struct Extension *extensions;
};
struct ServerHello {
	uint16_t legacy_version; //always 0x0303
	unsigned char random[32];
	uint8_t legacy_session_id_echo_length;
	unsigned char legacy_session_id_echo[32];
	uint16_t cipher_suite;
	uint8_t legacy_compression_method; // this vlaue should be 0 in tls 1.3
	uint16_t extensions_length;
	struct Extension *extensions;
};
struct HkdfLabel{
	uint16_t length;
	uint8_t label_length;
	unsigned char lable[255]; // "tls13 " + Label
	uint8_t contex_length;
	unsigned char contex[255];
};
void getUint16(int fd, uint16_t *out){
	unsigned char buf[2];
	read(fd, &buf, 2);
	*out = ((buf[0] << 8*(2-1)) | (buf[1] << 8*(2-2)));
//	printf("from func: %x\n",*out);
}
void writeUint16(int fd, uint16_t value){
	uint16_t out = htons(value);
	write(fd, &out, 2);
}
void writeUint24(int fd, uint32_t value){
	unsigned char a[3];
	uint32_t out = htonl(value);
	a[0] = (out>>8)&0xFF;
	a[1] = (out>>16)&0xFF;
	a[2] = (out>>24)&0xFF;
	write(fd, a, 3);
	printf("uint24: %x %x %x\n",a[0],a[1],a[2]);
}
void HKDF_Expand_Label(unsigned char *outPtr, unsigned char Secret[], uint16_t secret_length, unsigned char Label[], uint8_t label_length, unsigned char Contex[], uint8_t contex_length, uint16_t Length){
	unsigned char expandLabel[6+label_length];
	unsigned char tls13[] = {'t','l','s','1','3',' '};
	//compinde Lable and tls13
	for(int i = 0; i<sizeof(expandLabel);i++){
		if(i>6){expandLabel[i] = Label[i-6];}
		else{expandLabel[i] = tls13[i];}
	}
	unsigned char l[2+1+label_length+contex_length];

	uint16_t c = 0;

	l[c] =  (Length>>0)&0xFF; l[c+1] = (Length>>8)&0xFF; c+=2;
	l[c] = (uint8_t) 6+label_length; c++;

	for(int i = 0; i<sizeof(expandLabel);i++){
		l[i+c] = expandLabel[i];
	} c += sizeof(expandLabel);

	l[c] = contex_length; c++;
	for(int i = 0; i<contex_length;i++){
		l[c+i] = Contex[i];
	} c+= contex_length;

	crypto_kdf_hkdf_sha256_expand(outPtr, Length, l, sizeof(l), Secret);
}
void update_hash_uint16(crypto_hash_sha256_state *state, uint16_t num){
	uint16_t out = htons(num);
	unsigned char buf[] = {(out)&0xFF,(out>>8)&0xFF};
	crypto_hash_sha256_update(state, buf, 2);
}
void update_hash_uint24(crypto_hash_sha256_state *state, uint32_t num){
	uint32_t out = htonl(num);
	unsigned char buf[] = {(out>>8)&0xFF, (out>>16)&0xFF,(out>>24)&0xFF};
	crypto_hash_sha256_update(state,buf,3);
}
void update_hash_uint32(crypto_hash_sha256_state *state, uint32_t){
	uint32_t out = htonl(num);
	unsigned char buf[] =  {out&0xFF,(out>>8)&0xFF,(out>>16)&0xFF,(out>>24)&0xFF};
	crypto_hash_sha256_update(state,buf,4);
}
int main(){
	if(1){
		uint64_t a = 0x0123456789abcdf;
		uint32_t b = *(uint32_t*)&a;
		printf("b is %x\n",b);	
	}
	if(sodium_init() < 0){
		printf("sodium lib could not be init\n");
		return 1;
	}else{
		printf("sodium succefuly init\n");
	}

	if(crypto_aead_aes256gcm_is_available() == 0){
		printf("go mate with your self lib sodium\n");
		return 1;
	} else{
		printf("W in chat folks. AES is supported!\n");
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

	crypto_hash_sha256_state tHash;

	struct ClientHello ch = {0};
	struct TLSPlaintext record = {0};
	struct Handshake hs = {0};

	unsigned char lengthBuffer[2];

	read(acc, &record.type, 1);
	getUint16(acc, &record.legacy_record_version);
	getUint16(acc, &record.length);
	
	printf("type %u\n",record.type);
	printf("legacay version: %x\n",record.legacy_record_version);
	printf("length: %x\n", record.length);

	read(acc, &hs.msg_type,1);
       	crypto_hash_sha256_update(&tHash,&hs.msg_type,1);	

	unsigned char hsLengthBuffer[3];
	read(acc, &hsLengthBuffer, 3);
	hs.length = ((hsLengthBuffer[0] << 8*(3-1))|(hsLengthBuffer[1] << 8*(3-2))|(hsLengthBuffer[2] << 8*(3-3)));
	update_hash_uint24(&tHash,hs.length);

	printf("hs-msg type: %x\n", hs.msg_type);
	printf("hs-length %x\n",hs.length);

	read(acc, &ch.legacy_version, 2); update_hash_uint16(&tHash,ch.legacy_version);
	read(acc, ch.random, 32); crypto_hash_sha256_update(&tHash, ch.random);
	read(acc, &ch.legacy_session_id_length, 1); crypto_hash_sha256_update(&tHash,&ch.legacy_session_id_length, 1);
	read(acc, ch.legacy_session_id, ch.legacy_session_id_length); crypto_hash_sha256_update(&tHash, ch.legacy_session_id, ch.legacy_session_id_length);

	getUint16(acc, &ch.cipher_suites_length); update_hash_uint16(&tHash, ch.cipher_suites_length);
	ch.cipher_suites = malloc(ch.cipher_suites_length);
	
	if(ch.cipher_suites == NULL){printf("seg error is becuase null!\n");}

	read(acc, ch.cipher_suites, ch.cipher_suites_length); crypto_hash_sha256_update(&tHash, ch.cipher_suites, ch.cipher_suites_length);

	read(acc, &ch.legacy_compression_methods_length, 1); crypto_hash_sha256_update(&tHash, &ch.legacy_compression_mthods_length, 1);
	read(acc, ch.legacy_compression_methods, ch.legacy_compression_methods_length); crypto_hash_sha256_update(&tHash, ch.legacy_compression_methods, ch.legacy_compression_mthods_length);

	printf("ch-legacy version: %x\n",ch.legacy_version);
	printf("ch-random     : ");for(int i = 0; i<32;i++){printf("%X ",ch.random[i]);}printf("\n");	
	printf("ch-sessiond id: ");for(int i = 0; i<ch.legacy_session_id_length;i++){printf("%X ",ch.legacy_session_id[i]);}printf("\n");
	printf("ch-cipher suite length: 0x%x\n",ch.cipher_suites_length);

	for(int i = 0; i<ch.cipher_suites_length/2;i+=2){
		printf("0x%x%x, ",ch.cipher_suites[i],ch.cipher_suites[i+1]);
		if(ch.cipher_suites[i] == 0x013 && ch.cipher_suites[i+1] == 0x01){printf(" :yay: has sha256 gmc, ");}
	}
	printf("\n");

	printf("cu-legacy compresssio lnegth: %d\nch-legacy comperession: ",ch.legacy_compression_methods_length);
	for(int i = 0; i<ch.legacy_compression_methods_length;i++){printf("%X ",ch.legacy_compression_methods[i]);}printf("\n");

	getUint16(acc, &ch.extensions_length); update_hash_uint16(&tHash, ch.extensions_length);
	
	ch.extensions = malloc(ch.extensions_length);

	int readEx = 0;
	int index = 0;
	while(1){
		struct Extension *ex = malloc(sizeof(struct Extension));
		if(ex == NULL){printf("malloc failed!");return 1;}

		uint16_t type, length;
		getUint16(acc, &type);
		getUint16(acc, &length);
		readEx += 4;

		ex->extension_data = malloc(length);
		if(ex->extension_data == NULL){printf("malloc failed! fir extension data");}
		read(acc, ex->extension_data, length);
		readEx += length;

		ex->extension_type = type;
		ex->extension_data_length = length;

		ch.extensions[index] = *ex;
		index++;

		if(length <= 0){printf("thats realy weaird length is les than 0 type: %x\n",type);}

		//printf("index: %d readEx: %d ch.ex_len: %d length: %d type: %x\n",index,readEx,ch.extensions_length,length,type);
		if(readEx >= ch.extensions_length){break;}

	}
	crypto_hash_sha256_update(&tHash, ch.extensions, ch.extensions_length);
	ch.extensions_length = index;
	/*
	for(int i = 0; i<ch.extensions_length;i++){
		printf("type %d length 0x%x body: ",ch.extensions[i].extension_type,ch.extensions[i].extension_data_length);
		for(int j = 0; j<ch.extensions[i].extension_data_length;j++){
			printf("%x ",ch.extensions[i].extension_data[j]);
		}
		printf("\n");
	}
	*/
	//printf("index %d",index);

	unsigned char client_pk[crypto_box_PUBLICKEYBYTES];
	printf("----------------- start extension parsing ---------------------------\n");
	for(int i = 0; i<index;i++){
		if(ch.extensions[i].extension_type == 51){ // id for key_share
			printf("key_share extension recinized!\n");
			struct Extension key_share = ch.extensions[i];
			unsigned char *data = key_share.extension_data;
			for(int j = 2; j<key_share.extension_data_length;){
				uint16_t group = ((data[j+0] << 8) | (data[j+1]<<0)); j+=2;
				uint16_t key_exchange_length = ((data[j+0]<<8)|(data[j+1]<<0)); j+=2;
				printf("key_share group: 0x%x key_share length: %d\n",group,key_exchange_length);
				if(group == 0x001d){ // named_group for ECDHE X25519
					printf("group recnoized!\n");
					unsigned char *key_exchange = malloc(key_exchange_length); if(key_exchange == NULL){printf("malloc failed! for key_exchange\n");return 1;}
					for(int k = 0; k<key_exchange_length;k++){
						key_exchange[k] = data[k+j];
					}
					if(key_exchange_length != crypto_kx_PUBLICKEYBYTES){
						printf("we have a problem cap!\n");
						return 1;
					}
					for(int k = 0; k<crypto_box_PUBLICKEYBYTES;k++){client_pk[k] = key_exchange[k];printf("%x ",client_pk[k]);}
					printf("\nclients key has been parsed and read!\n");
					free(key_exchange);
					break;
				}
				j+=key_exchange_length;

			}
			break;
		}
	}
	
	//record = {}; i guess just dont reset?

	record.type = 22; // handshake
	record.legacy_record_version = 0x0303;
	record.length = 0;

	//reset handshake
	hs.msg_type = 2;
	hs.length = 0;

	struct ServerHello sh = {0};
	sh.legacy_version = 0x0303;
	randombytes_buf(&sh.random, 32);

	record.length += 34;

	sh.legacy_session_id_echo_length = ch.legacy_session_id_length;
	memcpy(sh.legacy_session_id_echo, ch.legacy_session_id,sizeof(ch.legacy_session_id));

	record.length += 1 + ch.legacy_session_id_length;

	sh.cipher_suite = 0x1301; // TLS_AES_128_GCM_SHA256
	sh.legacy_compression_method = 0; // must be ZERO 0
	
	record.length += 3;

	int numberOfExtensions = 2;

	unsigned char server_pk[crypto_box_PUBLICKEYBYTES];
	unsigned char server_sk[crypto_box_SECRETKEYBYTES];
	unsigned char sharedsecret[crypto_scalarmult_BYTES];

	randombytes_buf(server_sk, sizeof(server_sk));
	crypto_scalarmult_base(server_pk, server_sk);
	if(crypto_scalarmult(sharedsecret, server_sk, client_pk)!=0){
		printf("sharedsecret calculation did not work!\n");
	}else{printf("shared secret calulation has worked!\n");}


	
	//sh.extensions = malloc(sizeof(struct Extension) * numberOfExtensions);
	//if(sh.extensions == NULL){printf("malloc failed! when reserving sh extensions!");}
	record.length += 2; //extension prefix
	uint16_t ex_length = 0;

	struct Extension supported_versions = {0};
	supported_versions.extension_type = 43;
	supported_versions.extension_data_length = 2;
	supported_versions.extension_data = malloc(2); 
	supported_versions.extension_data[0] = 0x03; supported_versions.extension_data[1] = 0x04; // TLS 1.3
	//sh.extensions[0] = supported_versions;
	ex_length += 2 + 2 + 2; // type + length + payload/data

	
	uint16_t key_share_group = 0x001d;
	struct Extension key_share = {0};
	key_share.extension_type = 51; ex_length += 2;
	key_share.extension_data_length = 2 + 2 + crypto_box_PUBLICKEYBYTES; // group + vectorPrefix + vector(server_pk)
	ex_length += 2;

	uint16_t group = 0x001d; // named group for x25519
	ex_length += 2;
	uint16_t key_exchange_length = crypto_box_PUBLICKEYBYTES; ex_length += 2;
	ex_length += crypto_box_PUBLICKEYBYTES; // server public key 

	record.length += ex_length;
	hs.length = record.length - 2 -2 + 4; // lost 4 bytes of data some where. in the recod length i never added the handshake bytes. 4 bytes.
	record.length += 4; // bytes for the handshake layer

	//record
	write(acc,&record.type,1);
	writeUint16(acc, record.legacy_record_version);
	writeUint16(acc, record.length);
	printf("record_length: %d\nhandshake_length: %d\nextension_length: %d\nsupported_versions length: %d\n",record.length,hs.length,ex_length,supported_versions.extension_data_length);

	//handshake
	write(acc, &hs.msg_type, 1);
	writeUint24(acc, hs.length);
	
	//server_hello
	writeUint16(acc, sh.legacy_version);
	write(acc, sh.random, 32);
	write(acc, &sh.legacy_session_id_echo_length, 1);
	write(acc, sh.legacy_session_id_echo, sh.legacy_session_id_echo_length);
	writeUint16(acc,sh.cipher_suite);
	write(acc, &sh.legacy_compression_method,1);

	//extensions
	writeUint16(acc, ex_length);
	//supported_versions
	writeUint16(acc, supported_versions.extension_type);
	writeUint16(acc, supported_versions.extension_data_length);
	write(acc, supported_versions.extension_data, 2);
	//key_share
	writeUint16(acc, key_share.extension_type);
	writeUint16(acc, key_share.extension_data_length);
	writeUint16(acc, key_share_group);
	writeUint16(acc, key_exchange_length);
	write(acc, server_pk, crypto_box_PUBLICKEYBYTES);

	uint16_t test = 0x1234;
	uint16_t nTest = htons(test);

	printf("%x %x\n",(nTest>>0)&0xFF,(nTest>>8)&0xFF);

	

	printf("sleeping for 2 second...\n");
	sleep(2);



	free(supported_versions.extension_data);
	free(sh.extensions);
	free(ch.cipher_suites);
	for(int i = 0; i<ch.extensions_length;i++){
		free(ch.extensions[i].extension_data);
	}
	free(ch.extensions);

	return 0;
}
