#include <chrono>
#include <ctime>
#include "channel.h"

int main(int argc, char *argv[]) {
	assert(argc == 4);
	uint16_t lport = atoi(argv[1]), rport = atoi(argv[2]);
	int myindex = atoi(argv[3]);
	constexpr uint64_t TIME = 1000;

	std::chrono::time_point<std::chrono::system_clock> start, end;
	std::chrono::duration<double> elapsed_seconds;
	std::time_t end_time;

	std::cerr << "Start testing channel establish" << std::endl;
	start = std::chrono::system_clock::now();
	ZChannel zc(myindex);
	zc.init(lport,rport,"127.0.0.1",ValuePair(100,100),4);
	zc.establish();
	end = std::chrono::system_clock::now();
	elapsed_seconds = end-start;
	end_time = std::chrono::system_clock::to_time_t(end);
	std::cerr << "finished computation at " << std::ctime(&end_time)
						<< "elapsed time (" << TIME <<" times): " << elapsed_seconds.count() << "s\n\n";

	std::cerr << "Start testing updating" << std::endl;
	std::cerr << "Going to update for " << TIME << " times" << std::endl;
	for(size_t i = 0; i < TIME; i++) {
		start = std::chrono::system_clock::now();
		zc.update(ValuePair::rand(200));
		end = std::chrono::system_clock::now();
		elapsed_seconds = end-start;
		end_time = std::chrono::system_clock::to_time_t(end);
		std::cout << "finished computation at " << std::ctime(&end_time)
							<< "elapsed time (" << TIME <<" times): " << elapsed_seconds.count() << "s\n\n";
	}

	std::cerr << "Start testing channel closure" << std::endl;
	start = std::chrono::system_clock::now();
	zc.close(myindex==0);
	end = std::chrono::system_clock::now();
	elapsed_seconds = end-start;
	end_time = std::chrono::system_clock::to_time_t(end);
	std::cerr << "finished computation at " << std::ctime(&end_time)
						<< "elapsed time (" << TIME <<" times): " << elapsed_seconds.count() << "s\n\n";
	return 0;
}
