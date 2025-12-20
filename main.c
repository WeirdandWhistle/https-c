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
void HKDF_Expand_Label(unsigned char *outPtr, unsigned char Secret[], unsigned char Label[], uint8_t label_length, unsigned char Contex[], uint8_t contex_length, uint16_t Length){
	unsigned char expandLabel[6+label_length];
	unsigned char tls13[] = {'t','l','s','1','3',' '};
	//compinde Lable and tls13
	printf("--- start label ---\n-");
	for(int i = 0; i<sizeof(expandLabel);i++){
		//printf(" %d ",i);
		if(i>=6){expandLabel[i] = Label[i-6];}
		else{expandLabel[i] = tls13[i];}
		printf("%c", expandLabel[i]);
	}
	printf("-\n--- end label ---\n");

	unsigned char l[2+1+sizeof(expandLabel)+1+contex_length];

	printf("label_elngth: %d expandLabel size: %d l size: %d\n", label_length, sizeof(expandLabel), sizeof(l));

	uint16_t c = 0;

	uint16_t nol = htons(Length);

	l[c] =  (nol>>0)&0xFF; l[c+1] = (nol>>8)&0xFF; c+=2;
	l[c] = (uint8_t) (6+label_length) & 0xFF; c++;
	printf("expaned label into l: \"");
	for(int i = 0; i<sizeof(expandLabel);i++){
		l[i+c] = expandLabel[i];
		printf("%c",l[i+c]);
	} c += sizeof(expandLabel); printf("\"\n");
	
	printf("Contex: 0x");
	l[c] = (contex_length) & 0xFF; c++;
	for(int i = 0; i<contex_length;i++){
		l[c+i] = Contex[i];
		printf("%02x", Contex[i]);
	} c+= contex_length; printf("\n");

	crypto_kdf_hkdf_sha256_expand(outPtr, Length, l, sizeof(l), Secret);

	//what the hell am i putting into this function debug part
	printf("the hell i am printing: \"");
	for(int i = 0; i<sizeof(l);i++){
		unsigned char cToPrint = l[i];
		if(isprint(cToPrint)){printf("%c",cToPrint);}
		else{printf("(0x%02x)",cToPrint);}
	}printf("\"\n");
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
void update_hash_uint32(crypto_hash_sha256_state *state, uint32_t num){
	uint32_t out = htonl(num);
	unsigned char buf[] =  {out&0xFF,(out>>8)&0xFF,(out>>16)&0xFF,(out>>24)&0xFF};
	crypto_hash_sha256_update(state,buf,4);
}
int main(){

	unsigned char abc[] = "123abc";

	printf("string %s length of that string %d\n",abc, sizeof(abc));
	printf("whats the c encodeing for 32? its '%c'\n",32);

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
	printf("crypto kedj bytes: %d\n",crypto_kdf_hkdf_sha256_KEYBYTES);

	if(crypto_aead_aes256gcm_is_available() == 0){
		printf("go mate with your self lib sodium\n");
		return 1;
	} else{
		printf("W in chat folks. AES is supported!\n");
	}
	// test cases
	if(1){
		unsigned char input_scalar[] = {0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a,
			0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4};

		unsigned char u_cord[] = {0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1, 0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9, 0x03,
			0xa6, 0xd0, 0xab, 0x1c, 0x4c};

		unsigned char output[32];

		if(crypto_scalarmult(output, input_scalar, u_cord)!= 0){
			printf("a error occured with the test vector!");
		} else {
			printf("output : 0x");
			for(int i = 0; i<32;i++){printf("%02x",output[i]);}
			printf("\n");

			printf("correct: 0xc3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552\n");
		}
	}
	//test case 2
	if(1){
		unsigned char input_scalar[] = {0x4b, 0x66, 0xe9, 0xd4, 0xd1, 0xb4, 0x67, 0x3c, 0x5a, 0xd2, 0x26, 0x91, 0x95, 0x7d, 0x6a, 0xf5, 0xc1, 0x1b, 0x64, 0x21, 0xe0, 0xea, 0x01, 0xd4, 0x2c, 0xa4, 0x16, 0x9e, 0x79, 0x18, 0xba, 0x0d};

		unsigned char u_cord[] = {0xe5, 0x21, 0x0f, 0x12, 0x78, 0x68, 0x11, 0xd3, 0xf4, 0xb7, 0x95, 0x9d, 0x05, 0x38, 0xae, 0x2c, 0x31, 0xdb, 0xe7, 0x10, 0x6f, 0xc0, 0x3c, 0x3e, 0xfc, 0x4c, 0xd5, 0x49, 0xc7, 0x15, 0xa4, 0x93};

		unsigned char output[32];

		if(crypto_scalarmult(output, input_scalar, u_cord)!= 0){
			printf("a error occured with the test vector!");
		} else {
			printf("output : 0x");
			for(int i = 0; i<32;i++){printf("%02x",output[i]);}
			printf("\n");

			printf("correct: 0x95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957\n");
		}

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
	crypto_hash_sha256_init(&tHash);

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
	read(acc, ch.random, 32); crypto_hash_sha256_update(&tHash, ch.random, 32);
	read(acc, &ch.legacy_session_id_length, 1); crypto_hash_sha256_update(&tHash,&ch.legacy_session_id_length, 1);
	read(acc, ch.legacy_session_id, ch.legacy_session_id_length); crypto_hash_sha256_update(&tHash, ch.legacy_session_id, ch.legacy_session_id_length);

	getUint16(acc, &ch.cipher_suites_length); update_hash_uint16(&tHash, ch.cipher_suites_length);
	ch.cipher_suites = malloc(ch.cipher_suites_length);
	
	if(ch.cipher_suites == NULL){printf("seg error is becuase null!\n");}

	read(acc, ch.cipher_suites, ch.cipher_suites_length); crypto_hash_sha256_update(&tHash, ch.cipher_suites, ch.cipher_suites_length);

	read(acc, &ch.legacy_compression_methods_length, 1); crypto_hash_sha256_update(&tHash, &ch.legacy_compression_methods_length, 1);
	read(acc, ch.legacy_compression_methods, ch.legacy_compression_methods_length); crypto_hash_sha256_update(&tHash, ch.legacy_compression_methods, ch.legacy_compression_methods_length);

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
		getUint16(acc, &type); update_hash_uint16(&tHash, type);
		getUint16(acc, &length); update_hash_uint16(&tHash, length);
		readEx += 4;

		ex->extension_data = malloc(length);
		if(ex->extension_data == NULL){printf("malloc failed! fir extension data");}
		read(acc, ex->extension_data, length); crypto_hash_sha256_update(&tHash, ex->extension_data, length);
		readEx += length;

		ex->extension_type = type;
		ex->extension_data_length = length;

		ch.extensions[index] = *ex;
		index++;

		if(length <= 0){printf("thats realy weaird length is les than 0 type: %x\n",type);}

		//printf("index: %d readEx: %d ch.ex_len: %d length: %d type: %x\n",index,readEx,ch.extensions_length,length,type);
		if(readEx >= ch.extensions_length){break;}

	}
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
	}else{printf("shared secret calulation has worked!\n");
	
		printf("server-secret-key: "); for(int i = 0; i<sizeof(server_sk);i++){printf("%02x",server_sk[i]);}printf("\n");
		printf("server-public-key: "); for(int i = 0; i<sizeof(server_pk);i++){printf("%02x",server_pk[i]);}printf("\n");
	
	}


	
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
	write(acc, &hs.msg_type, 1); crypto_hash_sha256_update(&tHash, &hs.msg_type, 1);
	writeUint24(acc, hs.length); update_hash_uint24(&tHash, hs.length);
	
	//server_hello
	writeUint16(acc, sh.legacy_version); update_hash_uint16(&tHash, sh.legacy_version);
	write(acc, sh.random, 32); crypto_hash_sha256_update(&tHash, sh.random ,32);
	write(acc, &sh.legacy_session_id_echo_length, 1); 			crypto_hash_sha256_update(&tHash, &sh.legacy_session_id_echo_length, 1);
	write(acc, sh.legacy_session_id_echo, sh.legacy_session_id_echo_length);crypto_hash_sha256_update(&tHash, sh.legacy_session_id_echo, sh.legacy_session_id_echo_length);
	writeUint16(acc,sh.cipher_suite); update_hash_uint16(&tHash, sh.cipher_suite);
	write(acc, &sh.legacy_compression_method,1); crypto_hash_sha256_update(&tHash, &sh.legacy_compression_method, 1);

	//extensions
	writeUint16(acc, ex_length); update_hash_uint16(&tHash, ex_length);
	//supported_versions
	writeUint16(acc, supported_versions.extension_type); update_hash_uint16(&tHash, supported_versions.extension_type);
	writeUint16(acc, supported_versions.extension_data_length);update_hash_uint16(&tHash, supported_versions.extension_data_length);
	write(acc, supported_versions.extension_data, 2); crypto_hash_sha256_update(&tHash, supported_versions.extension_data, 2);
	//key_share
	writeUint16(acc, key_share.extension_type); 	  update_hash_uint16(&tHash, key_share.extension_type);
	writeUint16(acc, key_share.extension_data_length);update_hash_uint16(&tHash, key_share.extension_data_length);
	writeUint16(acc, key_share_group); 		  update_hash_uint16(&tHash, key_share_group);
	writeUint16(acc, key_exchange_length); 		  update_hash_uint16(&tHash, key_exchange_length);

	write(acc, server_pk, crypto_box_PUBLICKEYBYTES); crypto_hash_sha256_update(&tHash, server_pk, crypto_box_PUBLICKEYBYTES);

	uint16_t test = 0x1234;
	uint16_t nTest = htons(test);

	printf("%x %x\n",(nTest>>0)&0xFF,(nTest>>8)&0xFF);

	unsigned char ZEROARRAY[32] = {0};

	//crypto_hash_sha256_state copy = tHash;
	//memcmp(&tHash, &copy, sizeof(crypto_hash_sha256_state));
	printf("shared_secret: "); for(int i = 0; i<sizeof(sharedsecret);i++){printf("%02x",sharedsecret[i]);} printf("\n");
	printf("trascipt_hash: ");
	unsigned char outHash[crypto_hash_sha256_BYTES];
	crypto_hash_sha256_final(&tHash, outHash);
	for(int i = 0; i < sizeof(outHash); i++){
		printf("%02x",outHash[i]);
	}printf("\n");
	printf("early_secret: ");
	unsigned char early_secret[crypto_kdf_hkdf_sha256_KEYBYTES];
	crypto_kdf_hkdf_sha256_extract(early_secret, ZEROARRAY, 32, ZEROARRAY, 32);
	
	for(int i = 0; i<32;i++){printf("%02x",early_secret[i]);}printf("\n");

	printf("derived_secret: ");
	unsigned char derived_secret[32] = {0x67};
	HKDF_Expand_Label(derived_secret, early_secret, "derived", sizeof("derived")-1, "", 0, 32);

	for(int i = 0; i<32;i++){printf("%02x",derived_secret[i]);}printf("\n");

	printf("handshake_secert\n");
	unsigned char handshake_secret[crypto_kdf_hkdf_sha256_KEYBYTES];
	crypto_kdf_hkdf_sha256_extract(handshake_secret, derived_secret,sizeof(derived_secret) ,sharedsecret, sizeof(sharedsecret));

	unsigned char server_hs_traffic_secret[32];
	HKDF_Expand_Label(server_hs_traffic_secret, handshake_secret,"s hs traffic", sizeof("s hs traffic")-1, outHash, sizeof(outHash), sizeof(server_hs_traffic_secret));
	//printf("derived secret[0]: %x\n",derived_secret[0]);
	printf("server hs tf secert\n");
	for(int i = 0; i<32; i++){
		printf("%02x", server_hs_traffic_secret[i]);
	} printf("\n");


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
