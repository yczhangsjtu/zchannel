#include <ctime>
#include "simulator.h"

int main() {
	Simulator simulator(0.5,1.0,50,50,true);
	while(simulator.getCurrentTime() < 14400000) {
		simulator.update();
	}
	std::cout << "[Finished] Unhandled transaction: " << simulator.unconfirmedTransactions() << std::endl;
	std::cout << "[Finished] Average confirm time: " << simulator.averageConfirm()/1000 << "s" << std::endl;
	return 0;
}
