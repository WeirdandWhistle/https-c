#include "tls_alert.h"

void alert_get_close(unsigned char *out){
	//out[0] = {21, 0x03, 0x03, 0x00, 0x02, 2, 0};
	out[0] = 2;
	out[1] = 0;
}
