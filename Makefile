CXX = g++
CXXFLAGS = -std=c++14 -Wall -Wextra -Ofast -DHAVE_PCAP=1 -static-libstdc++ -static-libgcc -lpcap -lpthread -lssl -lcrypto -I/usr/local/include -L/usr/local/lib

tunnel: main.cpp shared.cpp factory.cpp forwarders.cpp tls_helpers.cpp transport_base.cpp obfuscate_base.cpp simple_obfuscator.cpp xor_obfuscator.cpp mocker_base.cpp dns_mocker.cpp http_ws_mocker.cpp socks5_proxy.cpp udp_base.cpp udp_client.cpp udp_server.cpp dtls_server.cpp tcp_base.cpp tcp_client.cpp tcp_server.cpp icmp_base.cpp icmp_client.cpp icmp_server.cpp icmp6_base.cpp icmp6_client.cpp icmp6_server.cpp
	$(CXX) $(CXXFLAGS) main.cpp -o $@

clean:
	rm -f tunnel
