all: dns_attack

output.txt: dns_attack
	./dns_attack 192.168.1.104 7 8.8.8.8

dns_attack: dns_attack.c
	gcc dns_attack.c -o dns_attack
	sudo setcap cap_net_admin,cap_net_raw=eip dns_attack
clean:
	rm dns_attack