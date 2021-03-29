# 電腦安全概論 HW1
###### tags: `電腦安全概論`

[Raw Socket Tutorial](https://www.opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/)

## 執行步驟
1. 查Victim IPv4
    <br>`ipconfig`
    ![](https://i.imgur.com/Az14bUn.png) 
2. make
    <br>`>make`
    ![](https://i.imgur.com/RuERm5f.png)
3. 執行
    <br>`./dns_attack 192.168.1.104 7 8.8.8.8`
    * Attacker
        ![](https://i.imgur.com/QsUUegW.png)
    * Victim
        ![](https://i.imgur.com/qa9VW44.png)


### include file
```c
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <net/if.h>// struct ifreq
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>// struct ethhdr
#include <linux/if_packet.h>
#include <net/ethernet.h> //needless?
#include <errno.h>
```
很多ethernet header、IP header、UDP header的struct都可以在內建的header file裡面找到，不需要自己再額外定義
[C語言中資料結構(struct)的大小 - __attribute__((packed)) ](https://chunchaichang.blogspot.com/2010/06/cstruct-attributepacked.html)
### Root priviledge
linux強制使用者要有root priviledge(用sudo)才能使用raw socket
所以這邊我用這個方法
[Non-root users](https://squidarth.com/networking/systems/rc/2018/05/28/using-raw-sockets.html)
利用下列這段指令能讓non-root users執行dns_attack
`sudo setcap cap_net_admin,cap_net_raw=eip dns_attack`
### Check sum
[詳細計算方式](http://bruce690813.blogspot.com/2017/09/tcpip-checksum.html)
還蠻麻煩的
* IP header checksum
    1. 把IP header的資料以2 bytes為一組加總(checksum欄位除外)
    2. 進位補回
    3. 取補數
* UDP checksum
    1. Pseudo Header: Source IP + Destination IP + Protocol(0x0011) + L4 Header Length
    2. UDP header
    3. UDP Payload(注意要考慮byte長度為奇數的情況，應當幫他補上0. e.g.,0x??00)
### Wireshark
[在Linux安裝](https://www.itread01.com/content/1548586810.html)
[Non-root users](https://askubuntu.com/questions/748941/im-not-able-to-use-wireshark-couldnt-run-usr-bin-dumpcap-in-child-process)
其實直接sudo就好了==
[開關checksum validation](https://packetlife.net/blog/2008/aug/23/disabling-checksum-validation-wireshark/)
### Amplification 
DNSSEC, EDNS
### dig
運用dig可以直接由terminal發送dns request進行測試，意外測試到
<br>`dig ANY nctu.edu.tw @140.113.6.2`
![](https://i.imgur.com/DednJ7A.png)
3083的TCP、3084的DNS其實是同一個封包，Fragment成2塊，實際總長約2500，查看他的Request，發現差別在Additional Records
![](https://i.imgur.com/3N1vjHs.png)
實際照抄上去也會有同樣的效果
![](https://i.imgur.com/g9damJC.png)

