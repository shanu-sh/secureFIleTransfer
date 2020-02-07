#include<iostream>
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<arpa/inet.h>

using namespace std;

int main()
{
	int sockid;
	string server_address="127.0.0.1";
	int server_port=2000;

	if((sockid=socket(AF_INET,SOCK_STREAM,0))<0)
	{
		cout<<"Error in connection\n";
		exit(1);
	}

	struct sockaddr_in addr;
	addr.sin_family=AF_INET;
	addr.sin_port=htons(server_port);
	addr.sin_addr.s_addr=inet_addr(server_address.c_str());

	if(connect(sockid,(struct sockaddr *)&addr,sizeof(addr))<0)
	{
		cout<<"Error in connecting\n";
		exit(1);
	}

	int msg;
	recv(sockid,&msg,sizeof(msg),0);
	cout<<"Message is "<<msg<<"\n";
}
