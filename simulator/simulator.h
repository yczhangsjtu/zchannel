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

class BlockChain {
	std::vector<Block> blocks;
	std::vector<Transaction> transactions;
	uint64_t curr;
public:
	BlockChain():curr(0){}
	void insertTransaction(Transaction transaction) {
		// std::cout << "Inserting transaction " << transactions.size() << std::endl;
		transactions.push_back(transaction);
	}
	void createBlock(uint64_t time, uint64_t m, uint64_t k, uint64_t s,
			std::set<UserPair>& channels, std::vector<Payment>& payments) {
		std::cout << " Creating Block " << blocks.size();
		if(curr >= transactions.size()) {
			blocks.push_back(Block(time,curr,curr));
		} else {
			uint64_t from = curr, to = transactions.size();
			if(to-from > m) to = from+m;
			std::cout << " Transactions from " << from << " to " << to;
			blocks.push_back(Block(time,from,to));
			curr = to;
		}
		std::cout << " (Total " << transactions.size() << " transactions)";
		if(blocks.size() > k) {
			uint64_t index = blocks.size()-k-1;
			uint64_t from = blocks.at(index).getFrom();
			uint64_t to = blocks.at(index).getTo();
			uint64_t countpayment = 0, countchannel = 0;
			for(uint64_t i = from; i < to; i++) {
				transactions.at(i).setConfirm(time+s);
				if(transactions.at(i).hasPayment()) {
					payments.at(transactions.at(i).getPayment()).setConfirm(time+s);
					countpayment++;
				}
				if(transactions.at(i).isShare()) {
					UserPair userpair = payments.at(transactions.at(i).getPayment()).getUsers();
					auto iter = channels.find(userpair);
					assert(iter == channels.end());
					channels.insert(userpair);
					countchannel++;
				}
			}
			std::cout << " Confirmed " << countpayment << " payments." ;
			std::cout << " Established " << countchannel << " channels." ;
		}
	}

	inline uint64_t unconfirmedTransactions() const {
		return transactions.size() - curr;
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
		return (type == Type::BLOCK && rh.type == Type::PAYMENT) ||
			(type == Type::BLOCK && rh.type == Type::TRANSACTION) ||
			(type == Type::PAYMENT && rh.type == Type::TRANSACTION);
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
	std::set<UserPair> relations;
	std::set<UserPair> channels;
	std::set<UserPair> inwork;
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

	void insertEvent(uint64_t duration, Event::Type type) {
		uint64_t time = curr + duration * randExp();
		// std::cout << "Inserting event at " << time << std::endl;
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
		else if(event.getType() == Event::Type::TRANSACTION)
			handleTransactionEvent(event.getTransaction());
	}

	void handlePaymentEvent() {
		insertPaymentEvent();
		UserPair userpair;
		bool hasChannel;
		if(!rels.empty() && happenWithProbability(alpha)) {
			userpair = randomUserPairWithRelations();
		} else {
			userpair = randomUserPair();
			if(relations.find(userpair) == relations.end()) {
				relations.insert(userpair);
				rels.push_back(userpair);
			}
		}
		hasChannel = channels.find(userpair) != channels.end();
		if(hasChannel) {
			insertConfirmedPayment(userpair,curr+16*d);
		} else {
			uint64_t index = insertPayment(userpair);
			bool inWork = inwork.find(userpair) != inwork.end();
			if((!inWork) && happenWithProbability(beta)) {
				insertTransactionEvent(curr+p+r,0,false);
				insertTransactionEvent(curr+p+r,0,false);
				insertTransactionEvent(curr+2*p+r,index,true,true);
				inwork.insert(userpair);
			} else {
				insertTransactionEvent(curr+p+r,index);
			}
		}
	}

	void handleBlockEvent() {
		insertBlockEvent();
		std::cout << "[" << (double)curr/1000 << "s]";
		chain.createBlock(curr,m,k,s,channels,payments);
		std::cout << std::endl;
	}

	inline void handleTransactionEvent(Transaction transaction) {
		// std::cout << "[" << (double)curr/1000 << "s] Transaction happens " << transaction << std::endl;
		insertTransaction(transaction);
	}

public:
	Simulator(double alpha, double beta, uint64_t lambda, uint64_t n, bool useDAPPlus)
		:alpha(alpha), beta(beta), lambda(lambda), n(n), curr(0) {
		if(!useDAPPlus) {
			p = p1;
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

	bool update() {
		if(events.empty()) return false;
		Event event = *events.begin();
		events.erase(events.begin());
		handleEvent(event);
	}

	inline uint64_t unconfirmedTransactions() const {
		return chain.unconfirmedTransactions();
	}

	double averageConfirm() const {
		double sum = 0;
		uint64_t count = 0;
		for(uint64_t i = 0; i < payments.size(); i++) {
			const Payment &payment = payments.at(i);
			auto t = payment.getTime();
			auto c = payment.getConfirm();
			if(c > t) {
				count++;
				sum += c-t;
			}
		}
		return sum/count;
	}
};

#endif
