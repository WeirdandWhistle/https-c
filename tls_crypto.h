#ifndef TLS_CRYPTO
#define TLS_CRYPTO

void HKDF_Expand_Label(unsigned char *outPtr, unsigned char *Secret, unsigned char *Label, uint8_t label_length, unsigned char *Contex, uint8_t contex_length, uint16_t Length);

int create_record(unsigned char *outPtr, unsigned long long *out_len, unsigned char *message, unsigned long long mlen, unsigned char type, int padding_length, unsigned char *k, unsigned char *nouce);

void create_record_length(int *length, int mes_len, int padding_len);

#endif
