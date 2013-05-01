# makefile for my pcap fun
# aaron berger
# code@bergera.com

all: wbfs wbfclient wbfsf wbfsa wbfsnc wepfinder

wbfs: wbfpcap.o wbfwep.o wbfsqlite3.o
	g++ wepbruteforcer.c wbfwep.o wbfsqlite3.o wbfpcap.o -o wbfs -lpcap -lssl -lcrypto -lsqlite3	

wbfsf: wbfpcap.o wbfwep.o wbfsqlite3.o
	g++ -I/usr/include -I/usr/local/include -L/usr/local/lib -L/usr/lib -lpcap -lssl -lsqlite3 wbfwep.o wbfsqlite3.o wbfpcap.o -Wall -g -o wbfsf wepbruteforcerfull.c

wbfsa: wbfpcap.o wbfwep.o wbfsqlite3.o
	g++ -I/usr/include -I/usr/local/include -L/usr/local/lib -L/usr/lib -lpcap -lssl -lsqlite3 wbfwep.o wbfsqlite3.o wbfpcap.o -o wbfsa wepbruteforcerall.c

wbfsnc: wbfpcap.o wbfwep.o wbfsqlite3.o wbfncurses.o
	g++ -DCURSES wepbruteforcer.c wbfncurses.o wbfwep.o wbfsqlite3.o wbfpcap.o -o wbfsnc -lpcap -lssl -lcrypto -lsqlite3 -lncurses	

wepfinder: wbfpcap.o wbfwep.o wbfsqlite3.o
	g++ wepfinder.c wbfwep.o wbfsqlite3.o wbfpcap.o -Wall -g -o wepfinder -lpcap -lssl -lcrypto -lsqlite3 

wbfclient:
	g++ wbfclient.c -lssl -lcrypto -o wbfclient

wbfpcap.o: wbfpcap.c
	g++ -lpcap -c wbfpcap.c -o wbfpcap.o
wbfwep.o: wbfwep.c
	g++ -lcrypto -lssl -c wbfwep.c -o wbfwep.o
wbfsqlite3.o: wbfsqlite3.c wbfwep.o
	g++ -lsqlite3 wbfwep.o -c wbfsqlite3.c -o wbfsqlite3.o
wbfncurses.o: wbfncurses.c
	g++ -ltinfo -lncurses -lpthread -c wbfncurses.c -o wbfncurses.o

####################
# Miscellaneous    #
####################

clean:
	rm -f *~
	rm -f *.o
	rm -f *.core
	rm -f wbfclient wbfs wbfsf wbfsa wbfnc wepfinder 
