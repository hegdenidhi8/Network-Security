I have done my changes in simpletun.c, on top of existing code I added functionalities to build a miniVPN.

Server host: 192.168.15.4 --> vm1
Client host: 192.168.15.5 --> vm2

gcc -o simpletun simpletun.c -lssl -lcrypto 

./tunserver.sh on server

./tunClient.sh on client


Certificate Files Path is as below:
/home/cs528user/server.crt
/home/cs528user/server.key
"/home/cs528user/ca.crt"

On Server:
sudo ip addr add 10.0.1.1/24 dev tun0
sudo ifconfig tun0 up
sudo route add -net 10.0.2.0 netmask 255.255.255.0 dev tun0

On Client:
sudo ip addr add 10.0.2.1/24 dev tun0
sudo ifconfig tun0 up
sudo route add -net 10.0.1.0 netmask 255.255.255.0 dev tun0

Testing the tunnel
On Server:
$ ping 10.0.2.1
$ ssh 10.0.2.1
On Client:
$ ping 10.0.1.1
$ ssh 10.0.1.1
