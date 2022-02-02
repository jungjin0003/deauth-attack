#Makefile
all: deauth-attack

deauth-attack:
					g++ main.cpp deauth-attack.cpp -o deauth-attack -lpcap

clean:
		rm -f deauth-attack