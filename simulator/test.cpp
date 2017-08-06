#include <ctime>
#include <fstream>
#include "simulator.h"

// #define TEST_ALPHA
#define TEST_ALPHA_90

double test(double alpha, double beta, uint64_t n, bool useDAPP, uint64_t T, int repeat = 10) {
	double a = 0;
	for(int i = 0; i < repeat; i++) {
		Simulator simulator(alpha,beta,n,useDAPP);
		while(simulator.getCurrentTime() < T) {
			simulator.update();
		}
		a += simulator.averageConfirm();
	}
	return a/repeat;
}

using namespace std;

int main() {
	constexpr uint64_t T = 160*3600000; // Eighty hours
	constexpr uint64_t n = 100000;
	double conjest, conf;

	// Test original DAP scheme
#ifdef TEST_ORIGINAL_DAP
	{
		cerr << "Original DAP scheme" << endl;
		ofstream f("DAP.txt");
			double conf = test(0,0,n,false,T);
			f << conf << endl;
			cout << conf << endl;
		f.close();
	}
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

		for(double beta = 0; beta <= 1.0; beta += 0.1) {
			conf = test(alpha,beta,n,true,T);
			f << beta << '\t' << conf << endl;
			cout << beta << '\t' << conf << endl;

			conf = test(alpha,beta,n,true,T);
			f << beta << '\t' << conf << endl;
			cout << beta << '\t' << conf << endl;

			conf = test(alpha,beta,n,true,T);
			f << beta << '\t' << conf << endl;
			cout << beta << '\t' << conf << endl;

			conf = test(alpha,beta,n,true,T);
			f << beta << '\t' << conf << endl;
			cout << beta << '\t' << conf << endl;

			conf = test(alpha,beta,n,true,T);
			f << beta << '\t' << conf << endl;
			cout << beta << '\t' << conf << endl;

			conf = test(alpha,beta,n,true,T);
			f << beta << '\t' << conf << endl;
			cout << beta << '\t' << conf << endl;
		}
	f.close();
#endif

	test(0.9,1.0,n,true,T,1);
	return 0;
}
