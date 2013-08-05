pkt_analysis: webpcapd.c
	gcc -O3 -Wall -Wextra -lpcap `pkg-config --cflags --libs glib-2.0` -o webpcapd webpcapd.c

clean:
	rm -f webpcapd
