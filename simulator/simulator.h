#ifndef __SIMULATOR_H
#define __SIMULATOR_H

#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <set>
#include <map>
#include <cassert>

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
};

class Payment {
	uint64_t index, time, confirm;
	UserPair users;
public:
	Payment(uint64_t index, uint64_t time, uint64_t user1, uint64_t user2)
		:index(index),time(time),users(user1,user2){}
	Payment(uint64_t index, uint64_t time, UserPair users)
		:index(index),time(time),users(users){}
	inline uint64_t getIndex()const{return index;}
	inline uint64_t getTime()const{return time;}
	inline UserPair getUsers()const{return users;}
	inline void setConfirm(uint64_t t){confirm=t;}
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
};

class Block {
	uint64_t time, from, to;
public:
	Block(uint64_t time, uint64_t from, uint64_t to):time(time),from(from),to(to){}
	inline uint64_t getFrom()const{return from;}
	inline uint64_t getTo()const{return to;}
	inline uint64_t getTime()const{return time;}
};

class BlockChain {
	std::vector<Block> blocks;
	std::vector<Transaction> transactions;
	uint64_t curr;
public:
	BlockChain():curr(0){}
	void insertTransaction(Transaction transaction) {
		transactions.push_back(transaction);
	}
	void createBlock(uint64_t time, uint64_t m, uint64_t k, uint64_t s,
			std::map<UserPair,bool>& relations, std::vector<Payment>& payments) {
		if(curr >= transactions.size()) {
			blocks.push_back(Block(time,curr,curr));
			return;
		}
		uint64_t from = curr, to = transactions.size();
		if(to-from > m) to = from+m;
		blocks.push_back(Block(time,from,to));
		if(blocks.size() > k) {
			uint64_t index = blocks.size()-k-1;
			uint64_t from = blocks.at(index).getFrom();
			uint64_t to = blocks.at(index).getTo();
			for(uint64_t i = from; i < to; i++) {
				transactions.at(i).setConfirm(time+s);
				if(transactions.at(i).hasPayment()) {
					payments.at(transactions.at(i).getPayment()).setConfirm(time+s);
				}
				if(transactions.at(i).isShare()) {
					UserPair userpair = payments.at(transactions.at(i).getPayment()).getUsers();
					auto iter = relations.find(userpair);
					assert(iter != relations.end());
					iter->second = true;
				}
			}
		}
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
		return type == Type::BLOCK && rh.type == Type::PAYMENT;
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
	std::set<Event> events;
	std::vector<Payment> payments;
	std::map<UserPair,bool> relations;
	std::vector<UserPair> rels;
	BlockChain chain;
	uint64_t curr;

	// Parameters
	double alpha, beta;
	uint64_t lambda;
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

	inline static double randExp() {
		return -log((double)rand()/RAND_MAX);
	}

	inline static uint64_t randUint32() {
		return (((uint64_t)rand())<<16) |
					 ((uint64_t)rand());
	}

	inline static uint64_t randUint64() {
		return (((uint64_t)rand())<<48) |
					 (((uint64_t)rand())<<32) |
					 (((uint64_t)rand())<<16) |
					 (((uint64_t)rand()));
	}

	inline static bool happenWithProbability(double p) {
		return (double)rand()/RAND_MAX < p;
	}

	UserPair randomUserPairWithRelations() const {
		assert(!rels.empty());

		size_t x = ((((double)randUint32())/RAND_MAX)*rels.size())/RAND_MAX;
		if(x >= rels.size()) x = rels.size() - 1;
		return rels.at(x);
	}

	UserPair randomUserPair() const {
		return UserPair(randUint32()%n,randUint32()%n);
	}

	void insertEvent(uint64_t duration, Event::Type type) {
		uint64_t time = curr + duration * randExp();
		events.insert(Event(type,time));
	}

	inline void insertPaymentEvent() {
		insertEvent(lambda,Event::Type::PAYMENT);
	}

	inline void insertBlockEvent() {
		insertEvent(mu,Event::Type::BLOCK);
	}

	inline void insertTransactionEvent(uint64_t time, uint64_t payment, bool hasPayment = true, bool isShare = false) {
		Event event = Event::transactionEvent(time,payment,hasPayment,isShare);
		events.insert(event);
	}

	inline uint64_t insertConfirmedPayment(UserPair users, uint64_t confirm) {
		uint64_t index = payments.size();
		Payment payment(index,curr,users);
		payment.setConfirm(confirm);
		payments.push_back(payment);
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
	}

	void handlePaymentEvent() {
		insertPaymentEvent();
		UserPair userpair;
		bool hasChannel;
		if(!rels.empty() && happenWithProbability(alpha)) {
			userpair = randomUserPairWithRelations();
			hasChannel = relations[userpair];
		} else {
			userpair = randomUserPair();
			hasChannel = false;
			if(relations.find(userpair) == relations.end()) {
				relations[userpair] = false;
				rels.push_back(userpair);
			}
		}
		if(hasChannel) {
			insertConfirmedPayment(userpair,curr+16*d);
		} else {
			uint64_t index = insertPayment(userpair);
			if(happenWithProbability(beta)) {
				insertTransactionEvent(curr+p+r,0,false);
				insertTransactionEvent(curr+p+r,0,false);
				insertTransactionEvent(curr+2*p+r,index,true,true);
			} else {
				insertTransactionEvent(curr+p+r,index);
			}
		}
	}

	void handleBlockEvent() {
		insertBlockEvent();
		chain.createBlock(curr,m,k,s,relations,payments);
	}

	inline void handleTransactionEvent(Transaction transaction) {
		insertTransaction(transaction);
	}

public:
	Simulator(double alpha, double beta, uint64_t lambda, uint64_t n, bool useDAPPlus)
		:alpha(alpha), beta(beta), lambda(lambda), n(n), curr(0) {
		if(!useDAPPlus) {
			p = p1;
			alpha = 0;
		} else {
			p = p2;
		}
		assert(alpha >= 0 && alpha <= 1);
		assert(beta >= 0 && beta <= 1);
		insertPaymentEvent();
		insertBlockEvent();
	}

	inline uint64_t getCurrentTime() const {
		return curr;
	}

	bool update() {
		if(events.empty()) return false;
		Event event = *events.begin();
		handleEvent(event);
		events.erase(*events.begin());
	}
};

#endif
