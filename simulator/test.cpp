#include <ctime>
#include <fstream>
#include "simulator.h"

// #define TEST_ORIGINAL_DAP
#define TEST_ALPHA
#define TEST_ALPHA_90

double test(double alpha, uint64_t n, uint64_t d, bool useDAPP, uint64_t T, double &strength) {
	double a = 0;
	double b = 0;
	int repeat = 1;
	for(int i = 0; i < repeat; i++) {
		Simulator simulator(alpha,n,d,useDAPP);
		while(simulator.getCurrentTime() < T) {
			simulator.update();
		}
		a += simulator.averageConfirm();
		b += simulator.paymentStrength;
	}
	strength = b/repeat;
	return a/repeat;
}

using namespace std;

int main() {
	constexpr uint64_t T = 72*3600000;
	constexpr uint64_t n = 100000;

	srand((unsigned)time(0));

	// Test original DAP scheme
#ifdef TEST_ORIGINAL_DAP
	cerr << "Original DAP scheme" << endl;
	ofstream f("DAP.txt");
	for(uint64_t d = 100; d <= 10000; d+=1000) {
		double str;
		double conf = test(0,n,d,false,T,str);
		f << d << "\t" << conf << "\t" << str << endl;
		cout << d << "\t" << conf << "\t" << str << endl;
		if(d == 100) d = 0;
	}
	f.close();
#endif

#ifdef TEST_ALPHA
	{
#ifdef TEST_ALPHA_10
		double alpha = 0.1;
		cerr << "Alpha 0.1" << endl;
		ofstream f("alpha10.txt");
#elif defined(TEST_ALPHA_50)
		double alpha = 0.5;
		cerr << "Alpha 0.5" << endl;
		ofstream f("alpha50.txt");
#elif defined(TEST_ALPHA_90)
		double alpha = 0.9;
		cerr << "Alpha 0.9" << endl;
		ofstream f("alpha90.txt");
#endif

		for(uint64_t d = 100; d <= 10000; d+=1000) {
			double str;
			double conf = test(alpha,n,d,true,T,str);
			f << d << "\t" << conf << "\t" << str << endl;
			cout << d << "\t" << conf << "\t" << str << endl;
			if(d == 100) d = 0;
		}
		f.close();
	}
#endif
	return 0;
}
