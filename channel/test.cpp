#include "channel.h"

int main() {
	uint16_t lport = 12345, rport = 54321;

	ZChannel zc(0);
	zc.init(lport,rport,ValuePair(100,100));
	return 0;
}
