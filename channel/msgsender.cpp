#include <iostream>
#include <string>
#include <ace/INET_Addr.h>
#include <ace/SOCK_Connector.h>
#include <ace/SOCK_Acceptor.h>
#include <ace/SOCK_Stream.h>
#include <ace/Log_Msg.h>

#include "channel.h"

int main() {
	ACE_SOCK_Acceptor acceptor;
	ACE_SOCK_Stream peer;
	ACE_INET_Addr addr;
	ACE_INET_Addr remote_addr;

	uint16_t lport = 12346;

	if(addr.set(lport) == -1) {
		std::cerr << "Failed to set port" << std::endl;
		return 1;
	}
	if(acceptor.open(addr) == -1) {
		std::cerr << "Failed to bind to address" << std::endl;
		return 1;
	}
	while(true) {
		if(acceptor.accept(peer,&remote_addr) == -1) {
			std::cerr << "Failed to accept" << std::endl;
			return 1;
		}
		std::cerr << "Accepted peer: " << remote_addr.get_host_name() << ":" << remote_addr.get_port_number() << std::endl;
		peer.disable(ACE_NONBLOCK);

		while(true) {
			std::string label, content, message;
			std::cerr << "Type label: ";
			std::cin >> label;
			std::cerr << "Type content: ";
			std::cin >> content;
			if(content == "rand") {
				content = uint256::rand().toHex();
			}
			message = label + "-" + content + ";";
			if(peer.send_n(message.c_str(),message.size()) == -1) {
				std::cout << "Failed to send message!" << std::endl;
				return 1;
			}
			std::cout << "Message sent: " << message << std::endl;
		}
	}
	return 0;
}
