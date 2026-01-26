#include "tls_alert.h"

void alert_get_close(unsigned char *out){
	//out[0] = {21, 0x03, 0x03, 0x00, 0x02, 2, 0};
	out[0] = 21;
	out[1] = 0x03;
	out[2] = 0x03;
	out[3] = 0x00;
	out[4] = 0x02;
	out[5] = 2;
	out[6] = 0;
}
