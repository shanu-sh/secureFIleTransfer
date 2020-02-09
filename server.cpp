#include<iostream>
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<openssl/des.h>
#include<arpa/inet.h>
#include<vector>
#include<string.h>
#include<time.h>
#include<algorithm>
#include<unistd.h>

using namespace std;

long q;
long x;
vector<long> key;

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
	char filename[1024];
}ReqServ;

typedef struct 
{
	int a;
}ReqCom;

typedef struct 
{
	char encodedmessage[1024];
}EncMsg;

typedef struct 
{
	int a;
}Disconnect;

typedef struct 
{
	Hdr hdr;
	union 
	{
		PubKey pubkey;
		ReqServ reqserv;
		ReqCom reqcom;
		EncMsg encmsg;
		Disconnect disconnect;
	};
}Msg;

long power(long x,long y,long n)
{
	long result=1;
	x%=n;
	while(y)
	{
		if(y&1)
			result=(result*x)%n;

		y>>=1;
		x=(x*x)%n;
	}
	return result;
}

bool isprime(long n)
{
	if(n<=1)
		return false;

	for(long i=2;i*i<=n;i++)
		if(n%i==0)
			return false;

	return true;
}

vector<long> findprimefactors(long n)
{
	vector<long> result;
	for(long i=2;i<n;i++)
	{
		if(n%i==0 && isprime(i))
			result.push_back(i);
	}

	return result;
}

long primitiveroot(long n)
{
	long fi=n-1;
	bool flag=false;

	vector<long> primefactors=findprimefactors(fi);
	for(long i=2;i<=fi;i++)
	{
		flag=false;
		for(auto j:primefactors)
		{
			if(power(i,fi/j,n)==1)
			{
				flag=true;
				break;
			}
		}
		if(flag==false)
			return i;
	}
	return -1;
}

long generaterandom(long n)
{
	return (rand()%n);
}

void computepubkey(PubKey &pkey)
{
	q=1151;
	pkey.q=1151;
	pkey.a=primitiveroot(pkey.q);
	x=generaterandom(pkey.a);
	pkey.y=power(pkey.a,x,pkey.q);
}

void showkeys()
{
	for(auto x:key)
		cout<<x<<"\n";
}

vector<int> computeblocks(int key)
{
	vector<int> result(64,0);
	int i=0;
	while(key)
	{
		result[i++]=key%2;
		key/=2;
	}

	reverse(result.begin(),result.end());

	vector<int> block;
	int temp=result[0];
	for(int i=1;i<=result.size();i++)
	{
		if(i%8==0)
		{
			block.push_back(temp);
			temp=0;
		}
		temp=temp*2+result[i];
	}
	return block;
}

char* encryption(char data[])
{
	vector<int> block=computeblocks(key[0]);
	
	DES_cblock Key1={(unsigned char)(block[0]),(unsigned char)(block[1]),(unsigned char)(block[2]),
		(unsigned char)(block[3]),(unsigned char)(block[4]),(unsigned char)(block[5]),
		(unsigned char)(block[6]),(unsigned char)(block[7])};

	vector<int> block1=computeblocks(key[1]);
	
	DES_cblock Key2={(unsigned char)(block1[0]),(unsigned char)(block1[1]),(unsigned char)(block1[2]),
		(unsigned char)(block1[3]),(unsigned char)(block1[4]),(unsigned char)(block1[5]),
		(unsigned char)(block1[6]),(unsigned char)(block1[7])};

	vector<int> block2 = computeblocks(key[2]);
	
	DES_cblock Key3={(unsigned char)(block2[0]),(unsigned char)(block2[1]),(unsigned char)(block2[2]),
		(unsigned char)(block2[3]),(unsigned char)(block2[4]),(unsigned char)(block2[5]),
		(unsigned char)(block2[6]),(unsigned char)(block2[7])};

	DES_key_schedule ks1;
	DES_key_schedule ks2;
	DES_key_schedule ks3;

    DES_cblock cblock = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	int stringLen=strlen(data)+1;

	printf("Plain Text : %s\n",data);

	char* cipher=new char[1024];
	char* text=new char[1024];
	memset(cipher,0,1024);
	memset(text,0,stringLen);

	DES_set_odd_parity(&cblock);

	if (DES_set_key(&Key1, &ks1)<0 || DES_set_key(&Key2, &ks2)<0 ||  DES_set_key(&Key3, &ks3)<0) {
	// printf("Key error, exiting ....\n");
	// return 1;
	}

	DES_ede3_cbc_encrypt((const unsigned char*)data,(unsigned char*)cipher,stringLen, &ks1, &ks2, &ks3,&cblock, DES_ENCRYPT);
	printf("Encrypted : %32.32s\n",cipher);

	memset(cblock,0,sizeof(DES_cblock));
	DES_set_odd_parity(&cblock);

	DES_ede3_cbc_encrypt((const unsigned char*)cipher,(unsigned char*)text,1024, &ks1, &ks2, &ks3,&cblock,DES_DECRYPT);
	printf("Decrypted : %s\n",text);

	return cipher;
}

void dhkeyexchange(Msg msg,int cfd)
{
	PubKey pkey;
		
	int y=msg.pubkey.y;

	//Sending my public key to client
	computepubkey(pkey);
	msg.hdr.opcode=10;
	msg.pubkey=pkey;
	send(cfd,(Msg*)&msg,sizeof(msg),0);

	long temp=power(y,x,q);
	key.push_back(temp);

	showkeys();
}

void terminateconnection(int cfd)
{
	Msg msg;
	msg.hdr.opcode=40;
	cout<<"Initiating termination\n";
	send(cfd,(Msg*)&msg,sizeof(msg),0);
}

void filetransfer(Msg msg,int cfd)
{
	cout<<"Starting of filetransfer\n";

	char filename[1024];

	strcpy(filename,msg.reqserv.filename);

	cout<<"Filename is "<<filename<<"\n";
	char *str=encryption("Hello world");

	cout<<"Encrypted message is "<<str<<"\n";
	msg.hdr.opcode=30;
	strcpy(msg.encmsg.encodedmessage,str);
	//msg.encmsg.encodedmessage=str;
	send(cfd,(Msg*)&msg,sizeof(msg),0);

	terminateconnection(cfd);
}

void processclient(int cfd)
{
	Msg msg;
	while(1)
	{
		recv(cfd,(Msg*)&msg,sizeof(msg),0);
		if(msg.hdr.opcode==10)
		{
			dhkeyexchange(msg,cfd);
		}
		else if(msg.hdr.opcode==20)
		{
			filetransfer(msg,cfd);
		}
		else if(msg.hdr.opcode==50)
		{
			cout<<"Disconnection request received\n";
			msg.hdr.opcode=50;
			send(cfd,(Msg*)&msg,sizeof(msg),0);
			close(cfd);
			exit(1);
		}
	}
}

int main()
{
	srand(time(0));
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

	processclient(cfd);
}
