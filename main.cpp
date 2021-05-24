#include <linux/if_packet.h>
#include <time.h>
#include <sys/timerfd.h>
#include <getopt.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <libgen.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netinet/if_ether.h>	//For ETH_P_ALL
#include <net/ethernet.h>	//For ether_header
#include <net/if.h>

#define MAX_EVENTS 16
#define MAXGATEWAY 4
#define MACADDRESSSIZE 6

unsigned char *header = NULL;
unsigned short seq=0;
unsigned int hostEntryIndex=0;
struct HostEntry *ipList=NULL;
unsigned int hostcount=0;
char str[INET_ADDRSTRLEN];
bool priority=false;
bool help=false;
bool average=false;
bool noscript=false;
char macgateway[MAXGATEWAY*MACADDRESSSIZE];
char srcipv4gateway[MAXGATEWAY*4];
unsigned int gatewaycount=0;
char macipstringbuffer[64];
char *softwarepath=NULL;
const char* scriptbase = "up.sh ";
struct sockaddr_ll socket_address;
struct ifreq if_idx;

char DEFAULT_IF[IFNAMSIZ];
#define BUF_SIZ		1024

uint16_t IDENTIFIER=0x7c25;
uint16_t SEQUENCE_NUMBER=0;
uint64_t TIMESTAMPS=0;
unsigned char dataIP[]={0x45,0x00,0x00,0x54,0x00,0xf7,0x40,0x00,0x40,0x01,0xca,0xef,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00};
unsigned char dataICMP[]={0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3c,0x5a,0x94,0x60,0x00,0x00,0x00,0x00,
                 0xc0,0x88,0x0d,0x00,0x00,0x00,0x00,0x00,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                 0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
                 0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37
};

enum ICMPState { OtherPacket, SamePacketButWrong, SamePacketAndValid };
void ProcessPacket(unsigned char* , int);
ICMPState ProcessICMPPacket(unsigned char* , int );
uint16_t ICMPChecksum(uint16_t *icmph, int len);

struct HostGateway
{
    bool replyReceived;
    bool lastState;
    bool results[100];
    unsigned int resultsCount;
    unsigned int resultSuccess;
};

struct HostEntry
{
    struct sockaddr_in *socket;//to store the decoded IPv4 destination, inet_pton(AF_INET,... .socket->sin_addr)
    char *address;
    uint16_t id;
    uint16_t sequence;
    int lastUpIP;
    int callSkip;//to retry each 15s the up/down script util work
    char* commandCallToScript;//command to retry
    HostGateway gateway[MAXGATEWAY];
};

const char *mactostring(const unsigned char * const mac)
{
    sprintf(macipstringbuffer,"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    return macipstringbuffer;
}

const char *mactostring(const char * const mac)
{
    return mactostring(reinterpret_cast<const unsigned char * const>(mac));
}

const char *iptostring(in_addr sin_addr)
{
    return inet_ntop(AF_INET, &sin_addr, macipstringbuffer, sizeof(macipstringbuffer));
}

void ProcessPacket(unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
        {
            const ICMPState rep=ProcessICMPPacket(buffer , size);
            if(rep!=ICMPState::OtherPacket)
            {
                if(rep==ICMPState::SamePacketAndValid)
                {
                    //printf("Reply found and ok\n");
                    unsigned int index=0;
                    while(index<gatewaycount)
                    {
                        if(memcmp(macgateway+index*MACADDRESSSIZE,buffer+MACADDRESSSIZE/*first is MAC of this computer, second is mac of the gateway*/,MACADDRESSSIZE)==0)
                        {
                            ipList[hostEntryIndex].gateway[index].replyReceived=true;
                            break;
                        }
                        index++;
                    }
                    if(index==hostcount)
                    {
                        printf("unknown gateway reply detect %s!=%s, gatewaycount: %d\n",mactostring(macgateway),mactostring(buffer+MACADDRESSSIZE),gatewaycount);
                        //exit(1);
                        return;
                    }
                    //printf("Reply found and ok next\n");
                }
                else
                    printf("Reply found BUT WRONG\n");
            }
        }
        break;
        default: //Some Other Protocol like ARP etc.
            break;
    }
}

ICMPState ProcessICMPPacket(unsigned char* dataICMP , int Size)
{
    if(Size<=1+1+2+2+2)
        return ICMPState::OtherPacket;
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(dataICMP  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
    struct icmphdr *icmph = (struct icmphdr *)(dataICMP + iphdrlen  + sizeof(struct ethhdr));
    uint16_t CHECKSUM_REPLY=0;
    memcpy(&CHECKSUM_REPLY,&icmph->checksum,sizeof(icmph->checksum));
    uint16_t zero16Bits=0;
    memcpy(&icmph->checksum,&zero16Bits,sizeof(icmph->checksum));
    const uint16_t CHECKSUM=ICMPChecksum(reinterpret_cast<uint16_t *>(dataICMP),sizeof(dataICMP));
    const bool checksumOk=memcmp(&CHECKSUM,&icmph->checksum,sizeof(icmph->checksum))!=0;
    if(!checksumOk)
        return ICMPState::OtherPacket;
    uint16_t IDENTIFIER_REPLY=0;
    uint16_t SEQUENCE_NUMBER_REPLY=0;
    memcpy(&IDENTIFIER_REPLY,&icmph->un.echo.id,sizeof(IDENTIFIER_REPLY));
    memcpy(&SEQUENCE_NUMBER_REPLY,&icmph->un.echo.sequence,sizeof(SEQUENCE_NUMBER_REPLY));
    if(IDENTIFIER==IDENTIFIER_REPLY && SEQUENCE_NUMBER==SEQUENCE_NUMBER_REPLY && checksumOk)
    {
        if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
            return ICMPState::SamePacketAndValid;
        else
            return ICMPState::SamePacketButWrong;//some thing is wrong like TTL expired (==11)
    }
    else
        return ICMPState::OtherPacket;
}

uint16_t ICMPChecksum(uint16_t *icmph, int len)
{
    uint16_t ret = 0;
    uint32_t sum = 0;
    uint16_t odd_byte;
    while (len > 1) {
        sum += *icmph++;
        len -= 2;
    }
    if (len == 1) {
        *(uint8_t*)(&odd_byte) = * (uint8_t*)icmph;
        sum += odd_byte;
    }
    sum =  (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    ret =  ~sum;
    return ret;
}

char *gettime()
{
    time_t t;
    time(&t);
    char* p = ctime(&t);
    const size_t l=strlen(p);
    p[l-1]='\0';
    return p;
}

void term(int signum)
{
    switch(signum)
    {
        case SIGTERM:
            printf("[%s] SIGTERM\n", gettime());
            break;
        case SIGINT:
            printf("[%s] SIGINT\n", gettime());
            break;
        default:
            printf("[%s] Signal %i\n", gettime(), signum);
            break;
    }
    exit(0);
}

unsigned short checksumICMP(void *b, int len)
{
    unsigned short *buf = reinterpret_cast<unsigned short *>(b);
    unsigned int sum=0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2 )
        sum += *buf++;
    if (len == 1 )
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

uint16_t checksumIP(const unsigned char *buffer, size_t len)
{
    uint32_t sum = 0;
    const unsigned char *end = buffer + len;

    while (buffer < end) {
        sum += buffer[0] << 8 | buffer[1];
        buffer += 2;
    }

    sum = (0xFFFF & sum) + (sum >> 16); // + carry;
    // again, if sum overflows
    const uint16_t final_sum = (0xFFFF & sum) + (sum >> 16);

    return ~final_sum;
}

void closeTimeForReply(HostEntry &h)
{

    int firstUpIP=-1;
    //sort if needed, output 0 to gatewaycount-1
    unsigned int indexOrdered[gatewaycount];
    for (unsigned int z = 0; z < gatewaycount; z++)
        indexOrdered[z]=z;
    if(priority || average)
    {
        for (unsigned int c = 0 ; c < gatewaycount - 1; c++)
        {
            for (unsigned int d = 0 ; d < gatewaycount - c - 1; d++)
            {
                HostGateway &hostA=h.gateway[indexOrdered[d]];
                HostGateway &hostB=h.gateway[indexOrdered[d+1]];
                if(average && hostA.resultsCount>=sizeof(hostA.results))
                    if (hostA.resultSuccess-3 > hostB.resultSuccess && hostA.resultSuccess*9/10>hostB.resultSuccess) /* For decreasing order use < */
                    {
                        unsigned swap       = indexOrdered[d];
                        indexOrdered[d]   = indexOrdered[d+1];
                        indexOrdered[d+1] = swap;
                    }
                //else if(priority) already sorted by priority
            }
        }
    }

    for (unsigned int z = 0; z < gatewaycount; z++)
    {
        {
            HostGateway &host=h.gateway[z];
            if(h.sequence>2)
            {
                if(host.resultsCount>=sizeof(host.results))
                {
                    if(host.results[0]==true)
                        host.resultSuccess--;//drop the first need decrease this counter
                    memcpy(host.results,host.results+1,sizeof(host.results)-1);
                    host.resultsCount--;
                }
                host.results[host.resultsCount]=host.replyReceived;
                host.resultsCount++;
                bool isFullyUp=false;
                bool isFullyDown=false;
                if(host.resultsCount>=8)
                {
                    /*printf("[%s] %s [%i][%i][%i][%i][%i][%i][%i][%i] host.resultsCount\n", gettime(), h.address,
                    host.results[host.resultsCount-8],host.results[host.resultsCount-7],
                    host.results[host.resultsCount-6],host.results[host.resultsCount-5],
                    host.results[host.resultsCount-4],host.results[host.resultsCount-3],
                    host.results[host.resultsCount-2],host.results[host.resultsCount-1],
                    host.resultsCount
                    );
                    printf("[%s] %s host.resultsCount>=8\n", gettime(), h.address);*/
                    isFullyUp=true;
                    isFullyDown=true;
                    unsigned int index=host.resultsCount-8;
                    while(index<host.resultsCount)
                    {
                        if(host.results[index]==false)
                            isFullyUp=false;
                        else
                            isFullyDown=false;
                        index++;
                    }
                }
                //printf("[%s] %s is now %i %i last %i\n", gettime(), h.address, isFullyUp, isFullyDown, host.replyReceived);
                if(isFullyUp && host.lastState==false)
                {
                    printf("[%s] %s is now UP\n", gettime(), h.address);
                    host.lastState=true;

                    struct stat sb;
                    if(stat("up-without-retry.sh",&sb)==0 && !noscript)
                    {
                        uint strlenaddr=0;
                        if(h.address!=NULL)
                            strlenaddr=strlen(h.address);
                        else
                            printf("internal bug: address null at %i\n", z);
                        char * saveUp = (char *)malloc(strlen(softwarepath)+strlen("up-without-retry.sh ")+strlenaddr+1);
                        strcpy(saveUp, softwarepath); /* copy name into the new var */
                        strcat(saveUp, "up-without-retry.sh "); /* copy name into the new var */
                        if(h.address!=NULL)
                            strcat(saveUp, h.address); /* add the extension */
                        printf("[%s] command %s at line %d\n", gettime(), saveUp, __LINE__);
                        system(saveUp);
                        free(saveUp);
                    }
                }
                if(isFullyDown && host.lastState==true)
                {
                    printf("[%s] %s is now DOWN\n", gettime(), h.address);
                    host.lastState=false;

                    struct stat sb;
                    if(stat("down-without-retry.sh",&sb)==0 && !noscript)
                    {
                        //save the trace route
                        uint strlenaddr=0;
                        if(h.address!=NULL)
                            strlenaddr=strlen(h.address);
                        else
                            printf("internal bug: address null at %i\n", z);
                        char * saveDown = (char *)malloc(strlen(softwarepath)+strlen("down-without-retry.sh ")+strlenaddr+1);
                        strcpy(saveDown, softwarepath); /* copy name into the new var */
                        strcat(saveDown, "down-without-retry.sh "); /* copy name into the new var */
                        if(h.address!=NULL)
                            strcat(saveDown, h.address); /* add the extension */
                        printf("[%s] command %s at line %d\n", gettime(), saveDown, __LINE__);
                        system(saveDown);
                        free(saveDown);
                    }
                }
                if(host.lastState==true)
                    if(firstUpIP==-1)
                        firstUpIP=z;
            }
        }
    }
    bool changeGateway=false;
    if(priority || average)
    {
        if(firstUpIP!=-1 && h.lastUpIP!=firstUpIP)
            changeGateway=true;
    }
    else
    {
        if(firstUpIP!=-1 && (h.lastUpIP==-1 || h.gateway[h.lastUpIP].lastState==false))
            changeGateway=true;
    }
    if(changeGateway)
    {
        if(h.lastUpIP>=0 && h.lastUpIP<(int)gatewaycount)
            printf("%s changeGateway\n", mactostring(macgateway+h.lastUpIP*MACADDRESSSIZE));
        else
            printf("NULL changeGateway, lastUpIP %d out of range %d\n", h.lastUpIP, gatewaycount);
        h.callSkip=0;
        h.lastUpIP=firstUpIP;
        if(h.lastUpIP>=0 && h.lastUpIP<(int)gatewaycount)
        {
            if(h.commandCallToScript!=NULL)
            {
                printf("%s full!=NULL\n", mactostring(macgateway+h.lastUpIP*MACADDRESSSIZE));
                free(h.commandCallToScript);
                struct stat sb;
                if(stat("up.sh",&sb)==0 && !noscript && firstUpIP!=-1)
                {
                    uint strlenaddr=0;
                    strlenaddr=strlen(iptostring(h.socket->sin_addr));
                    uint strlenmac=0;
                    strlenaddr=strlen(mactostring(macgateway+h.lastUpIP*MACADDRESSSIZE));
                    h.commandCallToScript = (char *)malloc(strlen(softwarepath)+strlen(scriptbase)+strlenaddr+1+strlenmac+1+50);
                    strcpy(h.commandCallToScript, softwarepath); /* copy name into the new var */
                    strcat(h.commandCallToScript, scriptbase); /* copy name into the new var */
                    strcat(h.commandCallToScript, iptostring(h.socket->sin_addr));
                    strcat(h.commandCallToScript, " ");
                    strcat(h.commandCallToScript, mactostring(macgateway+h.lastUpIP*MACADDRESSSIZE)); /* add the extension */
                    printf("%s is now first valide ip route (call: %s later to previous command failed)\n", mactostring(macgateway+h.lastUpIP*MACADDRESSSIZE), h.commandCallToScript);
                }
                else
                    h.commandCallToScript = NULL;
            }
            else
            {
                //printf("%s full==NULL\n", mactostring(macgateway+h.lastUpIP*MACADDRESSSIZE));
                struct stat sb;
                if(stat("up.sh",&sb)==0 && !noscript && firstUpIP!=-1)
                {
                    //printf("%s full==NULL a\n", mactostring(macgateway+h.lastUpIP*MACADDRESSSIZE));
                    uint strlenaddr=0;
                    strlenaddr=strlen(iptostring(h.socket->sin_addr));
                    uint strlenmac=0;
                    strlenaddr=strlen(mactostring(macgateway+h.lastUpIP*MACADDRESSSIZE));
                    h.commandCallToScript = (char *)malloc(strlen(softwarepath)+strlen(scriptbase)+strlenaddr+1+strlenmac+1+50);
                    strcpy(h.commandCallToScript, softwarepath); /* copy name into the new var */
                    strcat(h.commandCallToScript, scriptbase); /* copy name into the new var */
                    strcat(h.commandCallToScript, iptostring(h.socket->sin_addr));
                    strcat(h.commandCallToScript, " ");
                    strcat(h.commandCallToScript, mactostring(macgateway+h.lastUpIP*MACADDRESSSIZE));/* add the extension */
                    printf("[%s] %s is now first valide ip route (call: %s)\n", gettime(), mactostring(macgateway+h.lastUpIP*MACADDRESSSIZE), h.commandCallToScript);
                    printf("[%s] command %s at line %d\n", gettime(), h.commandCallToScript,__LINE__);
                    if(system(h.commandCallToScript)==0)
                    {
                        free(h.commandCallToScript);
                        h.commandCallToScript=NULL;
                    }
                    else
                        printf("call: %s failed, call later\n", h.commandCallToScript);
                }
                else
                    printf("%s full==NULL, noscript: %i, firstUpIP: %i\n", mactostring(macgateway+h.lastUpIP*MACADDRESSSIZE), noscript, firstUpIP);
            }
        }
        else
            printf("NULL changeGateway, lastUpIP %d out of range %d\n", h.lastUpIP, gatewaycount);
    }
    else if(h.commandCallToScript!=NULL)//recall
    {
        if(h.lastUpIP>=0 && h.lastUpIP<(int)gatewaycount)
            printf("%s full==NULL 2\n", mactostring(macgateway+h.lastUpIP*MACADDRESSSIZE));
        else
            printf("NULL full==NULL, lastUpIP %d out of range %d\n", h.lastUpIP, gatewaycount);
        h.callSkip++;
        if(h.callSkip>15)
        {
            h.callSkip=0;
            printf("[%s] re call: %s\n", gettime(), h.commandCallToScript);
            if(system(h.commandCallToScript)==0)
            {
                free(h.commandCallToScript);
                h.commandCallToScript=NULL;
            }
            else
                printf("call: %s failed, call later\n", h.commandCallToScript);
        }
    }
    /*else if(h.lastUpIP>=0 && h.lastUpIP<gatewaycount)
        printf("%s full==NULL 3\n", mactostring(macgateway+h.lastUpIP*MACADDRESSSIZE));*/
}

int main (int argc, char *argv[])
{
    softwarepath=argv[0];
    printf("[%s] Start\n", gettime());

    memset(&DEFAULT_IF,0,sizeof(DEFAULT_IF));
    memset(&macipstringbuffer,0,sizeof(macipstringbuffer));
    memset(&macgateway,0,sizeof(macgateway));
    memset(&srcipv4gateway,0,sizeof(srcipv4gateway));
    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = term;
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);

    hostcount=0;
    unsigned char buf[65535];

    if(argc<2) {
        printf("argument count error\n");
        exit(1);
    }

    dirname(argv[0]);
    strcat(argv[0], "/");
    printf("path=%s\n", argv[0]);

    ipList = (HostEntry *)malloc(sizeof(struct HostEntry) * 100);
    memset(ipList,0,sizeof(struct HostEntry) * 100);

    //parse the ip
    unsigned indexIpList=0;
    for (int i = 1; i < argc; i++) {
        if(argv[i][0]=='-')
        {
            if(argv[i][1]=='-')
            {
                if(strcmp(argv[i],"--help")==0)
                    help=true;
                else if(strcmp(argv[i],"--priority")==0)
                    priority=true;
                else if(strcmp(argv[i],"--average")==0)
                    average=true;
                else if(strcmp(argv[i],"--noscript")==0)
                    noscript=true;
                else
                {
                    printf("unknown argument: %s",argv[i]);
                    help=true;
                }
            }
            else
            {
                int index=1;
                while(argv[i][index]!='\0')
                {
                    if(argv[i][index]=='h')
                        help=true;
                    else if(argv[i][index]=='p')
                        priority=true;
                    else if(argv[i][index]=='a')
                        average=true;
                    else if(argv[i][index]=='n')
                        noscript=true;
                    else
                    {
                        printf("unknown argument: %s\n",argv[i]);
                        help=true;
                    }
                    index++;
                }
            }
        }
        else
        {

            if(strchr(argv[i], ':') != NULL)
            {
                if(gatewaycount>=MAXGATEWAY)
                    printf("%s ignored due to max %d mac address limit\n",argv[i],MAXGATEWAY);
                else
                {
                    char ipv4string[]="XXX.XXX.XXX.XXX";
                    unsigned char mac[6];
                    sscanf(argv[i], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx,%s", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5],ipv4string);
                    memcpy(macgateway+gatewaycount*6,mac,sizeof(mac));

                    struct in_addr rawIPv4;
                    memset(&rawIPv4,0,sizeof(rawIPv4));
                    const int convertResult=inet_pton(AF_INET,ipv4string,&rawIPv4);
                    if(convertResult!=1)
                    {
                           printf("not an IPv4 for second gateway part\n");
                           exit(1);
                    }
                    memcpy(srcipv4gateway+gatewaycount*4,&rawIPv4.s_addr,sizeof(rawIPv4.s_addr));

                    gatewaycount++;
                }
            }
            else
            {
                struct in_addr sin_addr;		/* Internet address.  */
                const int convertResult=inet_pton(AF_INET,argv[i],&sin_addr);
                if(convertResult!=1)
                {
                       printf("not an IPv4, take as if: %s\n",argv[i]);
                       strcat(DEFAULT_IF,argv[i]);
                }
                else
                {
                    if(indexIpList>=100)
                    {
                        printf("only can monitor 100 ips\n");
                        exit(1);
                    }

                    //printf("indexIpList[%d] new\n",indexIpList);
                    ipList[indexIpList].address=argv[i];
                    ipList[indexIpList].socket=(sockaddr_in *)malloc(sizeof(struct sockaddr_in));
                    memset(ipList[indexIpList].socket, 0, sizeof(*ipList[indexIpList].socket));
                    ipList[indexIpList].socket->sin_addr=sin_addr;
                    ipList[indexIpList].socket->sin_family = AF_INET;
                    ipList[indexIpList].id=rand()%65536;
                    ipList[indexIpList].sequence=1;
                    ipList[indexIpList].lastUpIP=-1;
                    ipList[indexIpList].callSkip=0;
                    ipList[indexIpList].commandCallToScript=NULL;

                    int indexGateway=0;
                    while(indexGateway<MAXGATEWAY)
                    {
                        HostGateway &h=ipList[indexIpList].gateway[indexGateway];
                        h.lastState=false;
                        h.replyReceived=false;
                        memset(h.results,0,sizeof(h.results));
                        h.resultsCount=0;
                        h.resultSuccess=0;
                        indexGateway++;
                    }
                    indexIpList++;
                }

/*                if ((ipList[indexIpList].sd = socket(PF_INET, SOCK_RAW|SOCK_NONBLOCK, proto->p_proto)) < 0) {
                    perror("socket");
                    return -1;
                }
                const int ttl  = 61;
                if (setsockopt(ipList[indexIpList].sd, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0)
                    perror("Set TTL option");
                if (fcntl(ipList[indexIpList].sd, F_SETFL, O_NONBLOCK) != 0 )
                    perror("Request nonblocking I/O");*/

            }
        }
    }
    if(help)
    {
        printf("usage: ./epollpingmultihoming [-h] [-p] [-a] [-n] ip <.. ip>\n");
        printf("-h     --help to show this help\n");
        printf("-p     --priority to the first have more priority, when back online switch to it\n");
        printf("-a     --average choice when have lower ping lost average, if near lost then use priority if -p defined\n");
        printf("-n     --noscript don't call external script\n");
        return -1;
    }

    printf("priority: %i, average: %i, noscript: %i\n", priority, average, noscript);
    {
        struct stat sb;
        if(stat("up.sh",&sb)!=0)
            printf("\e[31m\e[1mup.sh not found\e[39m\e[0m\n");
    }
    hostcount=indexIpList;

    memcpy(dataICMP+1+1+2,&IDENTIFIER,sizeof(IDENTIFIER));
    int sockfd;
    struct ifreq if_mac;
    int tx_len = 0;
    char sendbuf[BUF_SIZ];
    struct ether_header *eh = (struct ether_header *) sendbuf;

    /* Open RAW socket to send on */
    if ((sockfd = socket(AF_PACKET, SOCK_RAW|SOCK_NONBLOCK, htons(ETH_P_ALL))) == -1) {
        perror("socket");
        exit(255);
    }

    /* Get the index of the interface to send on */
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, DEFAULT_IF, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
    {
        perror("SIOCGIFINDEX");
        exit(255);
    }
    /* Get the MAC address of the interface to send on */
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, DEFAULT_IF, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
    {
        perror("SIOCGIFHWADDR");
        exit(255);
    }

    /* Construct the Ethernet header */
    memset(sendbuf, 0, BUF_SIZ);
    /* Ethernet header */
    eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
    eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
    eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
    eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
    eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
    eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
    eh->ether_dhost[0] = 0x00;
    eh->ether_dhost[1] = 0x00;
    eh->ether_dhost[2] = 0x00;
    eh->ether_dhost[3] = 0x00;
    eh->ether_dhost[4] = 0x00;
    eh->ether_dhost[5] = 0x00;
    /* Ethertype field */
    eh->ether_type = htons(ETH_P_IP);
    tx_len += sizeof(struct ether_header);
    tx_len+=sizeof(dataIP);
    tx_len+=sizeof(dataICMP);

    struct epoll_event evmain;
    memset(&evmain,0,sizeof(evmain));
    evmain.events = EPOLLIN;
    evmain.data.fd = sockfd;

    //pthread_setname_np(listen_thread, "listener");
    int timerfd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);

    //timer to ping at interval
    struct itimerspec it;
    it.it_interval.tv_sec  = 1;
    it.it_interval.tv_nsec = 0;
    it.it_value.tv_sec     = it.it_interval.tv_sec;
    it.it_value.tv_nsec    = it.it_interval.tv_nsec;

    //the event loop
    struct epoll_event ev, events[MAX_EVENTS];
    memset(&ev,0,sizeof(ev));
    int nfds, epollfd;

    /* Index of the network device */
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    /* Address length*/
    socket_address.sll_halen = ETH_ALEN;

    ev.events = EPOLLIN|EPOLLET;
    uint64_t value;

    if ((epollfd = epoll_create1(0)) == -1) {
        printf("epoll_create1: %s", strerror(errno));
        exit(1);
    }

    //timer event
    timerfd_settime(timerfd, 0, &it, NULL);
    ev.data.fd = timerfd;

    //add to event loop
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, timerfd, &ev) == -1) {
        printf("epoll_ctl failed to add timerfd: %s", strerror(errno));
        exit(1);
    }
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &evmain) == -1)
        fprintf(stderr, "epoll_ctl sfd");

    for (;;) {
        if ((nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1)) == -1)
            printf("epoll_wait error %s", strerror(errno));

        for (int n = 0; n < nfds; ++n) {
            if (events[n].data.fd == timerfd) {
                if (read(timerfd, &value, sizeof(uint64_t)) == -1) {
                    printf("failed to read timer, %s", strerror(errno));
                    exit(1);
                }
                //printf("ipList[%d]", hostEntryIndex);
                closeTimeForReply(ipList[hostEntryIndex]);

                HostEntry &h=ipList[hostEntryIndex];

                for (unsigned int z = 0; z < gatewaycount; z++)
                {
                    struct HostGateway * host=&h.gateway[z];
                    host->replyReceived=false;
                }

                IDENTIFIER=h.id;
                SEQUENCE_NUMBER=htobe16(h.sequence);
                if(h.sequence>=65535)
                    h.sequence=1;
                else
                    h.sequence++;
                //TIMESTAMPS=htobe64(0x609ECC8C);
                TIMESTAMPS=htole64(time(NULL));
                memcpy(dataICMP+1+1+2,&IDENTIFIER,sizeof(IDENTIFIER));
                memcpy(dataICMP+1+1+2+2,&SEQUENCE_NUMBER,sizeof(SEQUENCE_NUMBER));
                memcpy(dataICMP+1+1+2+2+2,&TIMESTAMPS,sizeof(TIMESTAMPS));
                uint16_t CHECKSUMZERO=0;
                memcpy(dataICMP+1+1,&CHECKSUMZERO,sizeof(CHECKSUMZERO));
                const uint16_t CHECKSUM=ICMPChecksum(reinterpret_cast<uint16_t *>(dataICMP),sizeof(dataICMP));
                memcpy(dataICMP+1+1,&CHECKSUM,sizeof(CHECKSUM));

                //printf("Send to %s\n",iptostring(h.socket->sin_addr));
                memcpy(dataIP+sizeof(dataIP)-4,&h.socket->sin_addr,4);
                /* Destination MAC */
                for (unsigned int z = 0; z < gatewaycount; z++)
                {
                    //printf("Send from %s\n",iptostring(*reinterpret_cast<in_addr *>(srcipv4gateway+4*z)));
                    memcpy(dataIP+sizeof(dataIP)-4-4,srcipv4gateway+4*z,4);

                    memcpy(dataIP+1+1+2+2+1+1+1+1,&CHECKSUMZERO,sizeof(CHECKSUMZERO));
                    const uint16_t checksumIPVar=htobe16(checksumIP(dataIP,sizeof(dataIP)));
                    memcpy(dataIP+1+1+2+2+1+1+1+1,&checksumIPVar,sizeof(checksumIPVar));

                    memcpy(socket_address.sll_addr,macgateway+MACADDRESSSIZE*z,MACADDRESSSIZE);
                    memcpy(eh->ether_dhost,macgateway+MACADDRESSSIZE*z,MACADDRESSSIZE);

                    memcpy(sendbuf+tx_len-sizeof(dataICMP)-sizeof(dataIP),dataIP,sizeof(dataIP));
                    memcpy(sendbuf+tx_len-sizeof(dataICMP),dataICMP,sizeof(dataICMP));

                    /* Send packet */
                    if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
                    {
                        printf("Send failed: %d, errno: %d, if_idx.ifr_ifindex: %d, tx_len: %d\n",hostEntryIndex,errno,if_idx.ifr_ifindex,tx_len);
                        exit(255);
                    }
                    /*else
                        printf("Send ok: %d, if_idx.ifr_ifindex: %d, tx_len: %d\n",hostEntryIndex,if_idx.ifr_ifindex,tx_len);*/
                }
                hostEntryIndex++;
                if(hostEntryIndex>=hostcount)
                    hostEntryIndex=0;
            }
            else if (events[n].data.fd == sockfd) {
                memset(buf, 0, sizeof(buf));
                socklen_t src_addr_size = sizeof(struct sockaddr_ll);
                sockaddr_ll socket_address_temp=socket_address;
                const ssize_t bytes = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&socket_address_temp, &src_addr_size);
                if (bytes > 0)
                {
                    ProcessPacket((unsigned char *)buf , bytes);
                    //printf("src_addr_size from receive: %d\n",src_addr_size);
                }
                else
                    perror("recvfrom");
            }
        }
    }

    return 0;
}
