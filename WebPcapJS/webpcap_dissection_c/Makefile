webpcap_dissection_test: disabled_protos.c disabled_protos.h webpcap_dissection.c webpcap_dissection.h webpcap_dissection_test.c
	gcc -Wall -Wextra -I/usr/include/wireshark `pkg-config --cflags --libs glib-2.0` -Wall -o webpcap_dissection_test webpcap_dissection.c webpcap_dissection_test.c disabled_protos.c -L/usr/lib/wireshark -lwiretap -lwireshark -lwsutil

clean:
	rm -f webpcap_dissection_test