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

	return 0;
}
