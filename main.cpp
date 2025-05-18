#include <sys/epoll.h>
#include <vector>
#include <string>
#include <cstring>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/timerfd.h>
#include <fcntl.h>
#include <signal.h>
#include <csignal>
#include <sys/wait.h>
#include <chrono>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define UNIXSOCKET_PATH "server.sock"
#define MAX_EVENTS 1024
#define EXTRAHCECK

const std::string scriptbase="up.sh ";

bool help=false;
bool priority=false;
bool average=false;
bool noscript=false;
char buffer[65535];
bool keepStatAfterRestartPID=false;

struct SourceIP
{
	int fd;
	bool lastState;
	bool results[100];
    uint8_t resetCount;
	unsigned int resultsCount;
	unsigned int resultSuccess;
	std::string IP;
	pid_t pingProcessId;
};

struct Destination
{
	std::string IP;
	int lastUpSourceIPIndex;
	int callSkip;//to retry each 15s the up/down script util work
	std::string commandCallToScript;//command to retry
	std::vector<SourceIP> sourceIP;
};

std::vector<Destination> destinations;

uint8_t stringreplaceAll(std::string& str, const std::string& from, const std::string& to)
{
    if(from.empty())
        return 0;
    size_t start_pos = 0;
    uint8_t count=0;
    while((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // In case 'to' contains 'from', like replacing 'x' with 'yx'
        count++;
    }
    return count;
}

std::string dateimteString()
{
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    std::string d(std::to_string(tm.tm_year + 1900)+"-"+std::to_string(tm.tm_mon + 1)+"-"+std::to_string(tm.tm_mday)+" "+std::to_string(tm.tm_hour)+":"+std::to_string(tm.tm_min)+":"+std::to_string(tm.tm_sec)+" ");
    stringreplaceAll(d,"\n","");
    stringreplaceAll(d,"\r","");
    stringreplaceAll(d,"\t","");
    return d;
}

// Signal handler for SIGCHLD
void sigchldHandler(int signum)
{
	int status;
	pid_t pid;
	// Reap all dead child processes
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
	{
        if (WIFEXITED(status))
            std::cout << /*dateimteString() deadlock, time is not signal safe, see https://man7.org/linux/man-pages/man7/signal-safety.7.html << */ "Child process " << pid << " terminated with exit status: " << WEXITSTATUS(status) << " signum: " << signum << " line " << __LINE__ << std::endl;
        else if (WIFSIGNALED(status))
            std::cout << /*dateimteString() deadlock, time is not signal safe, see https://man7.org/linux/man-pages/man7/signal-safety.7.html << */ "Child process " << pid << " killed by signal: " << WTERMSIG(status) << " signum: " << signum << " line " << __LINE__ << std::endl;

        for(unsigned int i =0; i<destinations.size(); i++)
		{
            Destination &dest=destinations[i];
            for(unsigned int j=0; j<dest.sourceIP.size(); j++)
			{
                SourceIP &sourceIP=dest.sourceIP[j];
                if(sourceIP.pingProcessId==pid)
				{
                    close(sourceIP.fd);
                    sourceIP.fd = -1;
                    if(!keepStatAfterRestartPID)
                    {
                        sourceIP.lastState=false;
                        memset(sourceIP.results,0,sizeof(sourceIP.results));
                        sourceIP.resultsCount=30;//if start from 0, then can be considered as UP in unstable case (util one packet is lost)
                        #if 30 >= 100
                        #error this number can t be greater than results[] count
                        #endif
                        if(sourceIP.resultsCount>sizeof(sourceIP.results))
                        {
                            std::cerr << "sourceIP.resultsCount>sizeof(sourceIP.results), sourceIP.resultsCount should always be < than " <<  sizeof(sourceIP.results) << std::endl;
                            sourceIP.resultsCount=0;
                        }
                        sourceIP.resultSuccess=0;
                    }
                    sourceIP.pingProcessId=0;
                    sourceIP.resetCount=0;
                    if(dest.lastUpSourceIPIndex==(int)j)
                        dest.lastUpSourceIPIndex=-1;
				}
			}
		}
	}
}


void createChild(SourceIP *pSourceIP,Destination *pDest)
{
	int fd[2];
	int ret = pipe(fd); //pipe creation
	if (ret == -1)
	{
		perror("Can't create pipe");
		exit(-1);
	}
	pid_t child = fork();
	if (child == 0) // child process for ping
	{
		close(fd[0]);
		dup2(fd[1],1);//redirect ping stdout in the pipe
        std::cout << dateimteString() << "ping -n -I " << pSourceIP->IP << " " << pDest->IP << " line " << __LINE__ << std::endl;
		execlp("ping","ping","-n","-I",pSourceIP->IP.c_str(),pDest->IP.c_str(),NULL);
	}
	else if (child > 0)
	{
		// Parent process continues
        std::cout << dateimteString() << "Parent process created child with PID: " << child << " line " << __LINE__ << std::endl;

		close(fd[1]);//close pipe in
		pSourceIP->fd=fd[0];
		pSourceIP->pingProcessId = child;
		int flags,s;
		flags=fcntl(pSourceIP->fd,F_GETFL,0);
        if(flags==-1) {std::cerr << "fcntl get flags error on " << pSourceIP->fd << " line " << __LINE__ << std::endl;abort();}
		flags|=O_NONBLOCK;
		s=fcntl(pSourceIP->fd,F_SETFL,flags);
        if(s==-1) {std::cerr << dateimteString() << "fcntl set flags error on " << pSourceIP->fd << " line " << __LINE__ << std::endl;abort();}
	}
	else
	{
		// Fork failed
        std::cerr << dateimteString() << "Failed to create a child process!" << " line " << __LINE__ << std::endl;
		exit(1);
	}
}


void closeTimeForReply(Destination &dest)
{

	int firstUpsourceIPIndex=-1;
	ssize_t readsize;
	//sort if needed, output 0 to h.gateway.size()-1
	/*    if(priority || average)
    {
        for (unsigned int c = 0 ; c < h.gateway.size() - 1; c++)
        {
            for (unsigned int d = 0 ; d < h.gateway.size() - c - 1; d++)
            {
                Destination &hostA=h.gateway[indexOrdered[d]];
                Destination &hostB=h.gateway[indexOrdered[d+1]];
                if(average && hostA.resultsCount>=sizeof(hostA.results))
                    if (hostA.resultSuccess-3 > hostB.resultSuccess && hostA.resultSuccess*9/10>hostB.resultSuccess)
                    {
                        unsigned swap       = indexOrdered[d];
                        indexOrdered[d]   = indexOrdered[d+1];
                        indexOrdered[d+1] = swap;
                    }
                //else if(priority) already sorted by priority
            }
        }
    }*/

	for (unsigned int z = 0; z < dest.sourceIP.size(); z++)
	{
		SourceIP &sourceIP=dest.sourceIP[z];
		if(sourceIP.resultsCount>=sizeof(sourceIP.results))
		{
			if(sourceIP.results[0]==true)
                if(sourceIP.resultSuccess>0)//bug prevent
                    sourceIP.resultSuccess--;//drop the first need decrease this counter
			memcpy(sourceIP.results,sourceIP.results+1,sizeof(sourceIP.results)-1);
			sourceIP.resultsCount--;
		}
		bool replyReceived=false;
#ifdef EXTRAHCECK
		memset(buffer,0,sizeof(buffer));
#endif
		errno=0;
		if(sourceIP.fd!=-1)
		{
			readsize=::read(sourceIP.fd,buffer,sizeof(buffer)-1);
		}
		else
		{
            std::cout << dateimteString() << "failed then restart " << dest.IP << " via " << sourceIP.IP << " is on " << sourceIP.fd << " line " << __LINE__ << std::endl;
			createChild(&sourceIP,&dest);
			z--;
            std::cout << dateimteString() << "again " << dest.IP << " via " << sourceIP.IP << " is on " << sourceIP.fd << " line " << __LINE__ << std::endl;
			continue;
		}
		if(readsize>10)
		{
			buffer[readsize]=0x00;
			if(readsize>1)
				if(buffer[readsize-1]=='\n')
					buffer[readsize-1]=0x00;
			const char *p = strstr(buffer,": icmp_seq=");
#ifdef EXTRAHCECK
			const char *p2 = strstr(buffer,(std::string("rom ")+dest.IP).c_str());
			if(p2!=NULL)
				replyReceived=(p!=NULL);
#else
            //std::cout << h.IP << " " << sourceIP.IP << " " << buffer << " line " << __LINE__ << std::endl;
			replyReceived=(p!=NULL);
#endif
		}
		else
		{
            if(errno!=11)
            std::cout << dateimteString() << "errno: " << errno << " readsize " << readsize << " read fd " << sourceIP.fd << " for " << dest.IP << " via " << sourceIP.IP << ", replyReceived: " << replyReceived << " buffer: " << buffer << " line " << __LINE__ << std::endl;
            /*if(readsize<0 || (errno!=0 && errno!=11))
            {
                ::close(sourceIP.fd);
                int fd[2];
                int ret = pipe(fd); //pipe creation
                if (ret == -1)
                {
                    perror("Can't create pipe");
                    exit(-1);
                }
                pid_t child = fork(); //create the ping process
                if (!child) // child process for ping
                {
                    close(fd[0]);
                    dup2(fd[1],1);//redirect ping stdout in the pipe
                    execlp("ping","ping","-n","-I",sourceIP.IP.c_str(),dest.IP.c_str(),NULL);
                }
                close(fd[1]);//close pipe in
                sourceIP.fd=fd[0];

                int flags,s;
                flags=fcntl(sourceIP.fd,F_GETFL,0);
                if(flags==-1) {std::cerr << "fcntl get flags error on " << sourceIP.fd << " line " << __LINE__ << std::endl;abort();}
                flags|=O_NONBLOCK;
                s=fcntl(sourceIP.fd,F_SETFL,flags);
                if(s==-1) {std::cerr << "fcntl set flags error on " << sourceIP.fd << " line " << __LINE__ << std::endl;abort();}
            }*/
		}
        //std::cout << "read fd " << sourceIP.fd << " for " << h.IP << " via " << sourceIP.IP << ", replyReceived: " << replyReceived << " buffer: " << buffer << " line " << __LINE__ << std::endl;
		//extract from ": icmp_seq="
		sourceIP.results[sourceIP.resultsCount]=replyReceived;
        if(replyReceived)
            sourceIP.resetCount=0;
        else
        {
            sourceIP.resetCount++;
            if(sourceIP.resetCount>=60)
            {
                kill(sourceIP.pingProcessId, SIGKILL);
                sourceIP.resetCount=0;
            }
        }
		sourceIP.resultsCount++;
		bool isFullyUp=false;
		bool isFullyDown=false;
		if(sourceIP.resultsCount>=8)
		{
			isFullyUp=true;
			isFullyDown=true;
			unsigned int index=sourceIP.resultsCount-8;
			while(index<sourceIP.resultsCount)
			{
				if(sourceIP.results[index]==false)
					isFullyUp=false;
				else
					isFullyDown=false;
				index++;
			}
		}
		if(isFullyUp && sourceIP.lastState==false)
		{
            std::cout << dateimteString() << dest.IP << " is now UP for " << sourceIP.IP << " line " << __LINE__ << std::endl;
			sourceIP.lastState=true;

			struct stat sb;
			if(stat("up-without-retry.sh",&sb)==0 && !noscript)
			{
				std::string cmd=std::string("/bin/bash up-without-retry.sh ")+dest.IP;
                std::cout << dateimteString()  << cmd << " line " << __LINE__ << std::endl;
				system(cmd.c_str());
			}
		}
		if(isFullyDown && sourceIP.lastState==true)
		{
            std::cout << dateimteString() << dest.IP << " is now DOWN for " << sourceIP.IP << " line " << __LINE__ << std::endl;
			sourceIP.lastState=false;

			struct stat sb;
			if(stat("down-without-retry.sh",&sb)==0 && !noscript)
			{
				std::string cmd=std::string("/bin/bash down-without-retry.sh ")+dest.IP;
                std::cout << dateimteString()  << cmd << " line " << __LINE__ << std::endl;
				system(cmd.c_str());
			}
		}
		if(sourceIP.lastState==true)
			if(firstUpsourceIPIndex==-1)
				firstUpsourceIPIndex=z;
	}
	bool changesourceIP=false;
	if(priority || average)
	{
		if(firstUpsourceIPIndex!=-1 && dest.lastUpSourceIPIndex!=firstUpsourceIPIndex)
			changesourceIP=true;
	}
	else
	{
		if(firstUpsourceIPIndex!=-1 && (dest.lastUpSourceIPIndex==-1 || dest.sourceIP[dest.lastUpSourceIPIndex].lastState==false))
			changesourceIP=true;
	}
    //std::cout << "firstUpsourceIPIndex: " << firstUpsourceIPIndex << ", changesourceIP: " << changesourceIP << ", h.lastUpSourceIPIndex: " << h.lastUpSourceIPIndex << std::endl;
	if(changesourceIP)
	{
		dest.callSkip=0;
		dest.lastUpSourceIPIndex=firstUpsourceIPIndex;
		if(dest.lastUpSourceIPIndex>=0 && dest.lastUpSourceIPIndex<(int)dest.sourceIP.size())
		{
			struct stat sb;
			if(stat("up.sh",&sb)==0 && !noscript && firstUpsourceIPIndex!=-1)
			{
				std::string cmd=std::string("/bin/bash up.sh ")+dest.sourceIP.at(dest.lastUpSourceIPIndex).IP+" "+dest.IP;
                std::cout << dateimteString()  << cmd << " line " << __LINE__ << std::endl;
				dest.commandCallToScript=cmd;
				if(system(cmd.c_str())==0)
					dest.commandCallToScript=std::string();
				else
                    std::cout << dateimteString() << "call: " << dest.commandCallToScript << " failed, call later" << " line " << __LINE__ << std::endl;
			}
			else
                std::cout << dateimteString() << "no script: " << dest.commandCallToScript << " failed, call later" << " line " << __LINE__ << std::endl;
		}
		else
            std::cout << dateimteString() << "script sourceIP out of range: " << dest.IP << " line " << __LINE__ << std::endl;
	}
	else
	{
		if(!dest.commandCallToScript.empty())//recall
		{
			if(dest.lastUpSourceIPIndex>=0 && dest.lastUpSourceIPIndex<(int)dest.sourceIP.size())
			{}
			else
                std::cout << dateimteString() << "lastUpIP " << dest.lastUpSourceIPIndex << " out of range " << dest.sourceIP.size() << " line " << __LINE__ << std::endl;
			dest.callSkip++;
			if(dest.callSkip>15)
			{
				dest.callSkip=0;
                std::cout << dateimteString() << "re call: " << dest.commandCallToScript << " line " << __LINE__ << std::endl;
				if(system(dest.commandCallToScript.c_str())==0)
					dest.commandCallToScript=std::string();
				else
                    std::cout << dateimteString() << "call: " << dest.commandCallToScript << " failed, call later" << " line " << __LINE__ << std::endl;
			}
		}
	}
}

int main(int argc, char *argv[])
{
	std::cout << dateimteString() << " start line " << __LINE__ << std::endl;
	if(argc<2) {
		printf("argument count error\n");
		exit(1);
	}
	//signal(SIGCHLD, SIG_IGN);

	struct sigaction sa;
	sa.sa_handler = sigchldHandler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;  // Restart interrupted system calls

	if (sigaction(SIGCHLD, &sa, nullptr) == -1)
	{
        std::cerr << "Failed to set signal handler for SIGCHLD" << " line " << __LINE__ << std::endl;
		exit(1);
	}

	//the event loop
	struct epoll_event ev, events[MAX_EVENTS];
	memset(&ev,0,sizeof(ev));
	int nfds, epollfd;

	ev.events = EPOLLIN|EPOLLET;

	if ((epollfd = epoll_create1(0)) == -1) {
		printf("epoll_create1: %s", strerror(errno));
		exit(1);
	}

    {
        sockaddr_un addr;
        int fd;

        if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
          perror("socket error");
          exit(-1);
        }

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, UNIXSOCKET_PATH, sizeof(addr.sun_path)-1);

        if(connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != -1)
        {
            while(1)
            {
                char buffer[1024*1024];
                memset(buffer,1,sizeof(buffer));
                const int s=::read(fd,buffer,sizeof(buffer));
                if(s>0)
                {
                    int index=0;
                    while(index<s)
                    {
                        if(buffer[index]==0x00)
                            break;
                        index++;
                    }
                    std::cout << buffer;
                    if(index<s)
                    {
                        std::cout << std::endl;
                        return 0;
                    }
                }
            }
        }
    }

    int sfd=-1;
    {
        if((sfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
        {
            std::cerr << "Can't create the unix socket: " << errno << std::endl;
            abort();
        }

        struct sockaddr_un local;
        local.sun_family = AF_UNIX;
        strcpy(local.sun_path,UNIXSOCKET_PATH);
        unlink(local.sun_path);
        int len = strlen(local.sun_path) + sizeof(local.sun_family);
        if(bind(sfd, (struct sockaddr *)&local, len)!=0)
        {
            std::cerr << "Can't bind the unix socket, error (errno): " << errno << std::endl;
            abort();
        }

        if(listen(sfd, 4096) == -1)
        {
            std::cerr << "Unable to listen, error (errno): " << errno << std::endl;
            abort();
        }
        chmod(UNIXSOCKET_PATH,(mode_t)S_IRWXU | S_IRWXG | S_IRWXO);

        int flags, s;
        flags = fcntl(sfd, F_GETFL, 0);
        if(flags == -1)
            std::cerr << "fcntl get flags error" << std::endl;
        else
        {
            flags |= O_NONBLOCK;
            s = fcntl(sfd, F_SETFL, flags);
            if(s == -1)
                std::cerr << "fcntl set flags error" << std::endl;
        }

        epoll_event event;
        memset(&event,0,sizeof(event));
        event.data.fd = sfd;
        event.events = EPOLLIN | EPOLLOUT | EPOLLET;
        //std::cerr << "EPOLL_CTL_ADD: " << fd << std::endl;
        if(epoll_ctl(epollfd,EPOLL_CTL_ADD, sfd, &event) == -1)
        {
            std::cerr << "epoll_ctl failed to add server: " << errno << std::endl;
            abort();
        }
    }

	struct epoll_event evmain;
	memset(&evmain,0,sizeof(evmain));
	evmain.events = EPOLLIN;

	std::vector<std::string> sourceIPTemp;
	bool nowIsIPtoMonitor=false;
	//parse the ip
	for (int i = 1; i < argc; i++)
	{
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
                else if(strcmp(argv[i],"--keepStat")==0)
                    keepStatAfterRestartPID=true;
				if(strcmp(argv[i],"--")==0)
					nowIsIPtoMonitor=true;
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
                    else if(argv[i][index]=='k')
                        keepStatAfterRestartPID=true;
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
			std::string s(argv[i]);

			if(nowIsIPtoMonitor)
			{
				//add to std::vector<Destination> destinations;
				Destination dest;
				dest.IP=s;
				dest.callSkip=0;
				dest.lastUpSourceIPIndex=-1;//none selected by default
				destinations.push_back(dest);
				unsigned int indexsourceIP=0;
				while(indexsourceIP<sourceIPTemp.size())
				{
					const std::string gTemp=sourceIPTemp.at(indexsourceIP);
					SourceIP sourceIP;
					sourceIP.IP=gTemp;
					sourceIP.lastState=false;
					//sourceIP.replyReceived=false;
					memset(sourceIP.results,0,sizeof(sourceIP.results));
					sourceIP.resultsCount=0;
					sourceIP.resultSuccess=0;
                    sourceIP.pingProcessId=0;
                    sourceIP.resetCount=0;
					createChild(&sourceIP,&dest);
                    std::cout << dateimteString() << "now " << dest.IP << " via " << sourceIP.IP << " is on " << sourceIP.fd << " line " << __LINE__ << std::endl;
					destinations.back().sourceIP.push_back(sourceIP);

					indexsourceIP++;
				}
			}
			else
				sourceIPTemp.push_back(s);
		}
	}
	if(help)
	{
		printf("usage: ./multihoming [-h] [-p] [-a] [-n] sourceIP sourceIP [sourceIP ..] -- ip [ip..]\n");
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

	int timerfd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);

	//timer to ping at interval
	struct itimerspec it;
	it.it_interval.tv_sec  = 1;
	it.it_interval.tv_nsec = 0;
	it.it_value.tv_sec     = it.it_interval.tv_sec;
	it.it_value.tv_nsec    = it.it_interval.tv_nsec;

	//timer event
	timerfd_settime(timerfd, 0, &it, NULL);
	ev.data.fd = timerfd;

	//add to event loop
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, timerfd, &ev) == -1) {
		printf("epoll_ctl failed to add timerfd: %s", strerror(errno));
		exit(1);
	}

	for (;;)
	{
		if ((nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1)) == -1)
			printf("epoll_wait error %s", strerror(errno));

		for (int n = 0; n < nfds; ++n) {
            if (events[n].data.fd == timerfd)
            {
                if(::read(timerfd, buffer, sizeof(buffer))!=sizeof(buffer))
                {}
                //just call 1s the function closeTimeForReply()
                unsigned int index=0;
                while(index<destinations.size())
                {
                    closeTimeForReply(destinations[index]);
                    index++;
                }
            }
            else if (events[n].data.fd == sfd)
            {
                sockaddr in_addr;
                socklen_t in_len = sizeof(in_addr);
                const int &infd = ::accept(sfd, &in_addr, &in_len);
                if(infd>=0)
                {
                    std::string toSend;
                    unsigned int indexDest=0;
                    while(indexDest<destinations.size())
                    {
                        const Destination &d=destinations.at(indexDest);
                        toSend+=std::string("callSkip: ")+std::to_string(d.callSkip)+"\n";
                        toSend+=std::string("commandCallToScript: ")+d.commandCallToScript+"\n";
                        toSend+=std::string("IP: ")+d.IP+"\n";
                        toSend+=std::string("lastUpSourceIPIndex: ")+std::to_string(d.lastUpSourceIPIndex)+"\n";
                        unsigned int indexSrc=0;
                        while(indexSrc<d.sourceIP.size())
                        {
                            const SourceIP &s=d.sourceIP.at(indexSrc);
                            toSend+=std::string(" ")+std::to_string(indexSrc)+":"+"\n";
                            toSend+=std::string("  fd: ")+std::to_string(s.fd)+"\n";
                            toSend+=std::string("  IP: ")+s.IP+"\n";
                            toSend+=std::string("  lastState: ")+std::to_string(s.lastState)+"\n";
                            toSend+=std::string("  pingProcessId: ")+std::to_string(s.pingProcessId)+"\n";
                            toSend+=std::string("  resetCount: ")+std::to_string(s.resetCount)+"\n";
                            //toSend+=std::string("  results: ")+s.results+"\n";
                            toSend+=std::string("  resultsCount: ")+std::to_string(s.resultsCount)+"\n";
                            toSend+=std::string("  resultSuccess: ")+std::to_string(s.resultSuccess)+"\n";
                            indexSrc++;
                        }
                        indexDest++;
                    }
                    ::write(infd,toSend.c_str(),toSend.size()+1);
                }
            }
		}
	}

	return 0;
}
