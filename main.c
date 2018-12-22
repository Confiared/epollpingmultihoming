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
#include <sys/epoll.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <libgen.h>

#define MAX_EVENTS 16

unsigned char *header = NULL;
unsigned short seq=0;
struct _host *ipList=NULL;
unsigned int hostcount=0;
char str[INET_ADDRSTRLEN];
struct _packet packet;

struct _packet
{
    struct icmphdr hdr;
    unsigned char msg[64];
};
struct _host
{
    char *address;
    struct sockaddr_in *socket;
    uint8_t lastStateList;
    bool replyReceived;
    bool lastState;
    int sd;
};

char *gettime()
{
    time_t t;
    time(&t);
    char* p = ctime(&t);
    const size_t l=strlen(p);
    p[l-1]='\0';
    return p;
}
unsigned short checksum(void *b, int len)
{
    unsigned short *buf = b;
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

void parseReply(void *buf)
{
    struct iphdr   *ip   = buf;
    struct icmphdr *icmp = buf + ip->ihl * 4;
    const uint16_t sequence=htons(icmp->un.echo.sequence);
    if(seq!=sequence)
        return;
    unsigned int index=0;
    while(index<hostcount)
    {
        if(memcmp(&ipList[index].socket->sin_addr,&ip->saddr,sizeof(ip->saddr))==0)
        {
            ipList[index].replyReceived=true;
            break;
        }
        index++;
    }
    /*if(index==hostcount)
    {
        printf("unknown reply detect\n");
        exit(1);
        return;
    }*/
}

void ping(struct sockaddr_in *addr, const int sd/*struct protoent *proto*/, unsigned short cnt/*, unsigned short hostid*/)
{
    packet.hdr.checksum = 0;
    packet.hdr.un.echo.sequence = htons(cnt);
    packet.hdr.checksum = checksum(&packet, sizeof(packet));

    if (sendto(sd, &packet, sizeof(packet), 0, (struct sockaddr*)addr, sizeof(*addr)) <= 0 )
    {}//perror("sendto");
}


int main (int argc, char *argv[])
{
    printf("[%s] Start\n", gettime());

    hostcount=argc-1;
    unsigned char buf[1024];
    ipList = malloc(sizeof(struct _host) * hostcount);
    struct sockaddr_in **addr = malloc(sizeof(struct sockaddr_in *) * hostcount);

    //resolv proto and pid
    int pid = getpid();
    struct protoent *proto =  getprotobyname("ICMP");

    if(argc<2) {
        printf("argument count error\n");
        exit(1);
    }

    dirname(argv[0]);
    strcat(argv[0], "/");
    printf("path=%s\n", argv[0]);

    //parse text
    char *name = "PINGD";
    unsigned char *header = malloc(strlen(name));
    for (unsigned int i = 0; i < strlen(name); i++)
        header[i] = name[i] + '0';

    //parse the ip
    char **hostlist=&argv[1];
    for (unsigned int i = 0; i < hostcount; i++) {
        ipList[i].address=hostlist[i];
        ipList[i].socket=malloc(sizeof(struct sockaddr_in));
        ipList[i].lastState=false;
        ipList[i].lastStateList=0;
        memset(ipList[i].socket, 0, sizeof(*ipList[i].socket));
        const int convertResult=inet_pton(AF_INET,ipList[i].address,&ipList[i].socket->sin_addr);
        if(convertResult!=1)
        {
               printf("not an IPv4");
               exit(1);
        }
        else
            ipList[i].socket->sin_family = AF_INET;

        if ((ipList[i].sd = socket(PF_INET, SOCK_RAW|SOCK_NONBLOCK, proto->p_proto)) < 0) {
            perror("socket");
            return -1;
        }
        const int ttl  = 61;
        if (setsockopt(ipList[i].sd, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0)
            perror("Set TTL option");
        if (fcntl(ipList[i].sd, F_SETFL, O_NONBLOCK) != 0 )
            perror("Request nonblocking I/O");

        addr[i]=ipList[i].socket;
    }

    //add main sd
    struct sockaddr_in addrmain;
    int sdmain=0;
    if ((sdmain = socket(PF_INET, SOCK_RAW|SOCK_NONBLOCK, proto->p_proto)) < 0 ) {
        printf("failed to open listening socket: %s", strerror(errno));
        exit(1);
    }
    struct epoll_event evmain;
    memset(&evmain,0,sizeof(evmain));
    evmain.events = EPOLLIN;
    evmain.data.fd = sdmain;

    //prepare the packet
    const unsigned char ver = 1;
    memset(&packet, 0, sizeof(packet));
    packet.hdr.type       = ICMP_ECHO;
    packet.hdr.un.echo.id = htons(pid);
    memcpy(packet.msg,      header,  5);
    memcpy(packet.msg + 5,  &ver,    1);
    memcpy(packet.msg + 6,  &ver, 2);
    unsigned long org_s  = 0;
    unsigned long org_ns = 0;
    //hostid = htons(hostid);
    //memcpy(pckt.msg + 6,  &hostid, 2);
    memcpy(packet.msg + 8,  &org_s,  4);
    memcpy(packet.msg + 12, &org_ns, 4);

    //pthread_setname_np(listen_thread, "listener");
    int fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);

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

    ev.events = EPOLLIN|EPOLLET;
    uint64_t value;

    if ((epollfd = epoll_create1(0)) == -1) {
        printf("epoll_create1: %s", strerror(errno));
        exit(1);
    }

    //timer event
    timerfd_settime(fd, 0, &it, NULL);
    ev.data.fd = fd;

    //add to event loop
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        printf("epoll_ctl failed to add timerfd: %s", strerror(errno));
        exit(1);
    }
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sdmain, &evmain) == -1)
        fprintf(stderr, "epoll_ctl sfd");

    const char* scriptbase = "up.sh ";
    char* full = NULL;
    int lastUpIP=-1;
    bool firstPing=true;
    int callSkip=0;
    for (;;) {
        if ((nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1)) == -1)
            printf("epoll_wait error %s", strerror(errno));

        for (int n = 0; n < nfds; ++n) {
            if (events[n].data.fd == fd) {
                if (read(fd, &value, sizeof(uint64_t)) == -1) {
                    printf("failed to read timer, %s", strerror(errno));
                    exit(1);
                }
                if(!firstPing)
                    seq++;
                int firstUpIP=-1;
                for (unsigned int z = 0; z < hostcount; z++)
                {
                    if(!firstPing)
                    {
                        ipList[z].lastStateList=(ipList[z].lastStateList*2) | ipList[z].replyReceived;
                        const uint8_t filterValue=(ipList[z].lastStateList & 0x0F);
                        if(ipList[z].lastState==true)
                            if(firstUpIP==-1)
                                firstUpIP=z;
                        if(filterValue == 0x0F && ipList[z].lastState==false)
                        {
                            printf("[%s] %s is now UP\n", gettime(), ipList[z].address);
                            ipList[z].lastState=true;
                        }
                        if(filterValue == 0x00 && ipList[z].lastState==true)
                        {
                            printf("[%s] %s is now DOWN\n", gettime(), ipList[z].address);
                            ipList[z].lastState=false;
                        }
                    }
                    ipList[z].replyReceived=false;
                    const int sd=ipList[z].sd;
                    struct sockaddr_in *saddr=addr[z];
                    ping(saddr, sd, seq);
                }
                if(firstUpIP!=-1 && lastUpIP!=firstUpIP)
                {
                    callSkip=0;
                    lastUpIP=firstUpIP;
                    if(full!=NULL)
                    {
                        free(full);
                        full = malloc(strlen(argv[0])+strlen(scriptbase)+strlen(ipList[lastUpIP].address)+1);
                        strcpy(full, argv[0]); /* copy name into the new var */
                        strcat(full, scriptbase); /* copy name into the new var */
                        strcat(full, ipList[lastUpIP].address); /* add the extension */
                        printf("%s is now first valide ip route (call: %s later to previous command failed)\n", ipList[lastUpIP].address, full);
                    }
                    else
                    {
                        full = malloc(strlen(argv[0])+strlen(scriptbase)+strlen(ipList[lastUpIP].address)+1);
                        strcpy(full, argv[0]); /* copy name into the new var */
                        strcat(full, scriptbase); /* copy name into the new var */
                        strcat(full, ipList[lastUpIP].address); /* add the extension */
                        printf("%s is now first valide ip route (call: %s)\n", ipList[lastUpIP].address, full);
                        if(system(full)==0)
                        {
                            free(full);
                            full=NULL;
                        }
                        else
                            printf("call: %s failed, call later\n", full);
                    }
                }
                else if(full!=NULL)//recall
                {
                    callSkip++;
                    if(callSkip>15)
                    {
                        callSkip=0;
                        printf("re call: %s\n", full);
                        if(system(full)==0)
                        {
                            free(full);
                            full=NULL;
                        }
                        else
                            printf("call: %s failed, call later\n", full);
                    }
                }
                firstPing=false;
            }
            if (events[n].data.fd == sdmain) {
                int bytes;
                unsigned int len = sizeof(addrmain);

                memset(buf, 0, sizeof(buf));
                bytes = recvfrom(sdmain, buf, sizeof(buf), 0, (struct sockaddr*) &addrmain, &len);
                if (bytes > 0)
                    parseReply(buf);
                else
                    perror("recvfrom");
            }
        }
    }

    return 0;
}
