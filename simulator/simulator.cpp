#include "simulator.h"

void BlockChain::createBlock(uint64_t time, uint64_t m, uint64_t k, uint64_t s, Simulator &sim) {
#ifdef DEBUG
	std::cerr << " Creating Block " << blocks.size();
#endif
	if(curr >= transactions.size()) {
		blocks.push_back(Block(time,curr,curr));
	} else {
		uint64_t from = curr, to = transactions.size();
		if(to-from > m) to = from+m;
#ifdef DEBUG
		std::cerr << " Transactions from " << from << " to " << to;
#endif
		blocks.push_back(Block(time,from,to));
		curr = to;
	}
#ifdef DEBUG
	std::cerr << " (Total " << transactions.size() << " transactions)";
#endif
	if(blocks.size() > k) {
		uint64_t index = blocks.size()-k-1;
		uint64_t from = blocks.at(index).getFrom();
		uint64_t to = blocks.at(index).getTo();
		uint64_t countpayment = 0, countchannel = 0;
		for(uint64_t i = from; i < to; i++) {
			transactions.at(i).setConfirm(time+s);
			if(transactions.at(i).hasPayment()) {
				sim.payments.at(transactions.at(i).getPayment()).setConfirm(time+s);
				sim.updateConfirm((time+s)-sim.payments.at(transactions.at(i).getPayment()).getTime());
				countpayment++;
			}
			if(transactions.at(i).isShare()) {
				UserPair userpair = sim.payments.at(transactions.at(i).getPayment()).getUsers();
				auto iter = sim.channels.find(userpair);
				assert(iter == sim.channels.end());
				sim.channels.insert(userpair);
				countchannel++;
			}
		}
#ifdef DEBUG
		std::cerr << " Confirmed " << countpayment << " payments." ;
		std::cerr << " Established " << countchannel << " channels (Total " << sim.channels.size() << " channels).";
		std::cerr << " Average confirm " << sim.averageConfirm() << " (" << sim.averageTransaction() << ")";
#endif
	}
}

void Simulator::handlePaymentEvent() {
	insertPaymentEvent();
	UserPair userpair;
	bool hasChannel;
	if(!rels.empty() && happenWithProbability(alpha)) {
		userpair = randomUserPairWithRelations();
	} else {
		userpair = randomUserPair();
		if(relations.find(userpair) == relations.end()) {
			insertRelationEvent(userpair);
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

bool Simulator::update() {
	if(events.empty()) return false;
	Event event = *events.begin();
	events.erase(events.begin());
	handleEvent(event);
}

