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

#define DEBUG

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
};

class Event {
public:
	enum class Type {BLOCK, PAYMENT, TRANSACTION, RELATION};
private:
	Type type;
	uint64_t time;
	Transaction payload;
	UserPair relation;
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
	inline static Event relationEvent(uint64_t time, UserPair users) {
		Event event(Type::RELATION,time);
		event.relation = users;
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
	inline UserPair getRelation() const {
		assert(type == Type::RELATION);
		return relation;
	}
};

class Simulator {
	friend BlockChain;
	std::set<Event> events;
	std::vector<Payment> payments;
	std::set<UserPair> relations;
	std::set<UserPair> channels;
	std::set<UserPair> inwork;
	std::vector<UserPair> rels;

	std::list<double> confirms;
	double confirmSum;

	BlockChain chain;
	uint64_t curr;

	// Parameters
	double alpha, beta;
	uint64_t n;

	uint64_t p;
	const uint64_t p1 = 98060;
	const uint64_t p2 = 101220;
	const uint64_t d = 100;
	const uint64_t r = 1000;
	const uint64_t s = 2750;
	const uint64_t k = 6;
	const uint64_t mu = 150000;
	const uint64_t m = 1000;
	const uint64_t interval = 3600000;

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
		assert(!rels.empty());

		size_t x = (((double)rand())/RAND_MAX)*rels.size();
		if(x >= rels.size()) x = rels.size() - 1;
		return rels.at(x);
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
		insertEvent(averageTransaction(),Event::Type::PAYMENT);
	}

	inline void insertBlockEvent() {
		insertEvent(mu,Event::Type::BLOCK);
	}

	inline void insertRelationEvent(UserPair userpair) {
		Event event = Event::relationEvent(curr+interval,userpair);
		events.insert(event);
	}

	inline void insertTransactionEvent(uint64_t time, uint64_t payment, bool hasPayment = true, bool isShare = false) {
		Event event = Event::transactionEvent(time,payment,hasPayment,isShare);
		events.insert(event);
	}

	inline void updateConfirm(double conf) {
		confirms.push_back(conf);
		confirmSum += conf;
		while(confirms.size() > 1000000) {
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
		else if(event.getType() == Event::Type::RELATION)
			handleRelationEvent(event.getRelation());
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
	}

	inline void handleTransactionEvent(Transaction transaction) {
		insertTransaction(transaction);
	}

	inline void handleRelationEvent(UserPair userpair) {
		if(relations.find(userpair) == relations.end()) {
			relations.insert(userpair);
			rels.push_back(userpair);
		}
	}

public:
	Simulator(double alpha, double beta, uint64_t n, bool useDAPPlus)
		:alpha(alpha), beta(beta), n(n), curr(0), confirmSum(0) {
		if(!useDAPPlus) {
			p = p1;
			this->beta = 0;
		} else {
			p = p2;
		}
		assert(this->alpha >= 0 && this->alpha <= 1);
		assert(this->beta >= 0 && this->beta <= 1);
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

	inline static double averageTransaction(double x) {
		x /= 1000;
		if(x >= 2001) return 301;
		if(x <= 1) return 1;
		return 1+(x-1)*0.15;
	}
	
	inline double averageTransaction() const {
		return averageTransaction(averageConfirm());
	}
};

#endif
