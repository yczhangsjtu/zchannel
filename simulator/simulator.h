#ifndef __SIMULATOR_H
#define __SIMULATOR_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <set>
#include <cassert>
#include <list>

// #define DEBUG

class UserPair {
	uint64_t user1, user2;
public:
	UserPair():user1(0),user2(0){}
	UserPair(uint64_t user1, uint64_t user2):user1(user1),user2(user2){
		assert(user1 != user2);
		if(user1 > user2) {
			uint64_t tmp = user1;
			user1 = user2;
			user2 = tmp;
		}
	}
	inline uint64_t getUser1() const {return user1;}
	inline uint64_t getUser2() const {return user2;}
	inline bool operator<(const UserPair& rh) const {
		if(user1 < rh.user1) return true;
		if(user1 > rh.user1) return false;
		return user2 < rh.user2;
	}
	inline std::string toString() const {
		return std::to_string(user1)+","+std::to_string(user2);
	}
};

inline std::ostream& operator<<(std::ostream& os, UserPair users) {
	os << "(" << users.toString() << ")";
	return os;
}

class Payment {
	uint64_t index, time, confirm;
	UserPair users;
public:
	Payment(uint64_t index, uint64_t time, uint64_t user1, uint64_t user2)
		:index(index),time(time),users(user1,user2),confirm(0){}
	Payment(uint64_t index, uint64_t time, UserPair users)
		:index(index),time(time),users(users),confirm(0){}
	inline uint64_t getIndex()const{return index;}
	inline uint64_t getTime()const{return time;}
	inline UserPair getUsers()const{return users;}
	inline void setConfirm(uint64_t t){
		assert(t>time);
		confirm=t;
	}
	inline uint64_t getConfirm()const{return confirm;}
};

class Transaction {
	uint64_t time, confirm, payment;
	bool isshare, haspayment;
public:
	Transaction(){}
	Transaction(uint64_t time, uint64_t payment, bool hasPayment=true, bool isShare=false)
		:time(time),confirm(0),payment(payment),isshare(isShare),haspayment(hasPayment)
	{}
	inline uint64_t getTime()const{return time;}
	inline uint64_t getPayment()const{return payment;}
	inline void setConfirm(uint64_t t){confirm=t;}
	inline bool isShare()const{return isshare;}
	inline bool hasPayment()const{return haspayment;}
	inline std::string toString() const {
		std::string ret = std::to_string(time);
		if(haspayment) ret += ":p"+std::to_string(payment);
		if(isshare) ret += ":s";
		if(confirm) ret += ":c"+std::to_string(confirm);
		return ret;
	}
};

inline std::ostream& operator<<(std::ostream& os, Transaction transaction) {
	os << "(" << transaction.toString() << ")";
	return os;
}

class Block {
	uint64_t time, from, to;
public:
	Block(uint64_t time, uint64_t from, uint64_t to):time(time),from(from),to(to){}
	inline uint64_t getFrom()const{return from;}
	inline uint64_t getTo()const{return to;}
	inline uint64_t getSize()const{return to-from;}
	inline uint64_t getTime()const{return time;}
};

class Simulator;
class BlockChain {
	std::vector<Block> blocks;
	std::vector<Transaction> transactions;
	uint64_t curr;
public:
	BlockChain():curr(0){}
	inline void insertTransaction(Transaction transaction) {
		transactions.push_back(transaction);
	}
	void createBlock(uint64_t time, uint64_t m, uint64_t k, uint64_t s, Simulator &sim);

	inline uint64_t unconfirmedTransactions() const {
		return transactions.size() - curr;
	}

	inline uint64_t congest() const {
		if(transactions.size() > curr+1000) return transactions.size()-curr-1000;
		return 0;
	}

	inline uint64_t unfill(uint64_t m) const {
		if(transactions.size() == curr && blocks.back().getSize() < m)
			return m - blocks.back().getSize();
		return 0;
	}
};

class Event {
public:
	enum class Type {BLOCK, PAYMENT, TRANSACTION};
private:
	Type type;
	uint64_t time;
	Transaction payload;
public:
	Event(Type type, uint64_t time):time(time),type(type){}
	inline uint64_t getTime()const{return time;}
	inline Type getType()const{return type;}
	inline bool operator<(const Event& rh) const {
		if(time < rh.time) return true;
		if(time > rh.time) return false;
		return type < rh.type;
	}
	inline static Event transactionEvent(uint64_t time, uint64_t payment, bool hasPayment = true, bool isShare = false) {
		Transaction transaction(time,payment,hasPayment,isShare);
		Event event(Type::TRANSACTION,time);
		event.setTransaction(transaction);
		return event;
	}
	inline void setTransaction(Transaction transaction) {
		assert(type == Type::TRANSACTION);
		payload = transaction;
	}
	inline Transaction getTransaction() const {
		assert(type == Type::TRANSACTION);
		return payload;
	}
};

class Simulator {
	friend BlockChain;
	std::set<Event> events;
	std::vector<Payment> payments;
	std::set<UserPair> channels;
	std::set<UserPair> inwork;

	std::list<double> confirms;
	double confirmSum;

	BlockChain chain;
	uint64_t curr;

	// Parameters
	double alpha;
	uint64_t n;
	bool useChannel;
	uint64_t r;
	uint64_t s;
	uint64_t d;

	uint64_t p;
	const uint64_t p1 = 98060;
	const uint64_t p2 = 101220;

	const uint64_t k = 6;
	const uint64_t mu = 150000;
	const uint64_t m = 1500;
	const uint64_t interval = 3600000;
	const uint64_t D = 5;

	inline static double randExp() {
		while(true) {
			auto a = rand();
			if(a != RAND_MAX) return -log((double)a/RAND_MAX);
		}
	}

	inline static bool happenWithProbability(double p) {
		return ((double)rand()/RAND_MAX) < p;
	}

	UserPair randomUserPairWithRelations() const {
		size_t x = rand()%(n-1);
		size_t y = x+rand()%D+1;
		if(y >= n) y = n-1;
		return UserPair(x,y);
	}

	bool hasRelation(UserPair userpair) const {
		return userpair.getUser2()-userpair.getUser1()<=D;
	}

	inline UserPair randomUserPair() const {
		uint64_t user1;
		uint64_t user2;
		while(true) {
			user1 = rand()%n;
			user2 = rand()%n;
			if(user1 != user2) break;
		}
		return UserPair(user1,user2);
	}

	inline void insertEvent(uint64_t duration, Event::Type type) {
		uint64_t time = curr + duration * randExp();
		events.insert(Event(type,time));
	}

	inline void insertPaymentEvent() {
		insertEvent(1000.0/paymentStrength,Event::Type::PAYMENT);
	}

	inline void insertBlockEvent() {
		insertEvent(mu,Event::Type::BLOCK);
	}

	inline void insertTransactionEvent(uint64_t time, uint64_t payment, bool hasPayment = true, bool isShare = false) {
		Event event = Event::transactionEvent(time,payment,hasPayment,isShare);
		events.insert(event);
	}

	inline void updateConfirm(double conf) {
		confirms.push_back(conf);
		confirmSum += conf;
		while(confirms.size() > 900000) {
			confirmSum -= confirms.front();
			confirms.pop_front();
		}
	}

	inline uint64_t insertConfirmedPayment(UserPair users, uint64_t confirm) {
		uint64_t index = payments.size();
		Payment payment(index,curr,users);
		payment.setConfirm(confirm);
		payments.push_back(payment);
		updateConfirm(confirm-curr);
		return index;
	}

	inline uint64_t insertPayment(UserPair users) {
		uint64_t index = payments.size();
		payments.push_back(Payment(index,curr,users));
		return index;
	}

	inline void insertTransaction(Transaction transaction) {
		chain.insertTransaction(transaction);
	}

	void handleEvent(Event event) {
		curr = event.getTime();
		if(event.getType() == Event::Type::PAYMENT)
			handlePaymentEvent();
		else if(event.getType() == Event::Type::BLOCK)
			handleBlockEvent();
		else if(event.getType() == Event::Type::TRANSACTION)
			handleTransactionEvent(event.getTransaction());
	}

	void handlePaymentEvent();

	inline void handleBlockEvent() {
		insertBlockEvent();
#ifdef DEBUG
		std::cerr << "[" << (double)curr/1000 << "s]";
#endif
		chain.createBlock(curr,m,k,s,*this);
#ifdef DEBUG
		std::cerr << std::endl;
#endif
		if(chain.congest()) paymentStrength -= 0.0002 * chain.congest();
		if(chain.unfill(m)) paymentStrength += 0.0002 * chain.unfill(m);
		if(paymentStrength < 1.0) paymentStrength = 1.0;
		if(paymentStrength > 1000) paymentStrength = 1000;
	}

	inline void handleTransactionEvent(Transaction transaction) {
		insertTransaction(transaction);
	}

public:
	double paymentStrength;
	Simulator(double alpha, uint64_t n, uint64_t d, bool useDAPPlus)
		:alpha(alpha), n(n), curr(0), confirmSum(0), useChannel(useDAPPlus), d(d), paymentStrength(1) {
		if(!useDAPPlus) {
			p = p1;
		} else {
			p = p2;
		}
		this->r = 5*d;
		this->s = 27*d;
		assert(this->alpha >= 0 && this->alpha <= 1);
		insertPaymentEvent();
		insertBlockEvent();
	}

	inline uint64_t getCurrentTime() const {
		return curr;
	}

	bool update();

	inline uint64_t unconfirmedTransactions() const {
		return chain.unconfirmedTransactions();
	}

	inline double averageConfirm() const {
		if(confirms.empty()) return 100000;
		return confirmSum/confirms.size();
	}
};

#endif
