#include "channel.h"

int main(int argc, char *argv[]) {
	assert(argc == 4);
	uint16_t lport = atoi(argv[1]), rport = atoi(argv[2]);
	int myindex = atoi(argv[3]);

	ZChannel zc(myindex);
	zc.init(lport,rport,"127.0.0.1",ValuePair(100,100));
	zc.establish();
	zc.update(ValuePair(80,120));
	zc.update(ValuePair(85,115));
	zc.close(myindex==0);
	return 0;
}
