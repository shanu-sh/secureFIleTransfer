#include<iostream>
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<arpa/inet.h>

using namespace std;

typedef struct
{
	int opcode;
	int s_addr;
	int d_addr;
}Hdr;

typedef struct
{
	long q;
	long y;
	long a;
}PubKey;

typedef struct 
{
	int a;
}ReqServ;

typedef struct 
{
	int a;
}ReqCom;

typedef struct 
{
	int a;
}EncMsg;

typedef struct 
{
	int a;
}Disconnect;



int main()
{
	int sockid;
	if((sockid=socket(AF_INET,SOCK_STREAM,0))<0)
	{
		cout<<"Error in connection\n";
		exit(1);
	}

	struct sockaddr_in serveraddr;
	serveraddr.sin_family=AF_INET;
	serveraddr.sin_port=htons(2000);
	serveraddr.sin_addr.s_addr=inet_addr("127.0.0.1");
	
	if(bind(sockid,(struct sockaddr*)&serveraddr,sizeof(serveraddr))<0)
	{
		cout<<"Error in binding\n";
		exit(1);
	}

	if(listen(sockid,1)<0)
	{
		cout<<"listen() failed\n";
		exit(1);

	}

	struct sockaddr_in clientaddr;
	int clen=sizeof(clientaddr);

	int cfd;

	if((cfd=accept(sockid,(struct sockaddr *)&clientaddr,(socklen_t*)&clen))<0)
	{
		cout<<"Accept failed\n";
		exit(1);
	}
	
	int msg=10;
	send(cfd,&msg,sizeof(msg),0);
	cout<<"Message sent\n";

}
