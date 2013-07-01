pkt_analysis: pcap_server.c
	gcc -O3 -Wall -Wextra -lpcap `pkg-config --cflags --libs glib-2.0` -o pcap_server pcap_server.c

clean:
	rm -f pcap_server
