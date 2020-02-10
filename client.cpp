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

char* decryption(char data[])
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

	char* text=new char[1024];
	memset(text,0,stringLen);

	DES_set_odd_parity(&cblock);

	if (DES_set_key(&Key1, &ks1)<0 || DES_set_key(&Key2, &ks2)<0 ||  DES_set_key(&Key3, &ks3)<0) {
	// printf("Key error, exiting ....\n");
	// return 1;
	}

	DES_ede3_cbc_encrypt((const unsigned char*)data,(unsigned char*)text,1024, &ks1, &ks2, &ks3,&cblock,DES_DECRYPT);
	printf("Decrypted : %s\n",text);
	return text;

}

void terminateconnection(int sockid)
{
	Msg msg;
	msg.hdr.opcode=50;
	send(sockid,(Msg*)&msg,sizeof(msg),0);
	cout<<"Shutting down Initiated\n";

	recv(sockid,(Msg*)&msg,sizeof(msg),0);

	if(msg.hdr.opcode==50)
	{
		cout<<"Bye bye\n";
		close(sockid);
		exit(1);
	}
}

void filetransfer(int sockid)
{
	Msg msg;
	char filename[1024];
	cout<<"Enter the file you want to transfer\n";
	cin>>filename;

	msg.hdr.opcode=20;
	strcpy(msg.reqserv.filename,filename);
	send(sockid,(Msg*)&msg,sizeof(msg),0);

	//Reveive the file size from server
	memset(msg.encmsg.encodedmessage,'\0',1024);
	recv(sockid,(Msg*)&msg,sizeof(msg),0);
	cout<<msg.encmsg.encodedmessage<<"Hoorah\n";
	char * text=decryption(msg.encmsg.encodedmessage);

	int size=stoi(string(text));
	cout<<size;

	//Recieve the file from server

	int n;

	FILE *fp;
	fp=fopen("temp.txt","w");

	int buffsize=1024;
    char chunk[buffsize];

	
		// memset(msg.encmsg.encodedmessage,'\0',1024);
		// recv(sockid,(Msg*)&msg,sizeof(msg),0);
		// if(msg.hdr.opcode==40)
		// {
		// 	cout<<"FIle transfer successfull\n";
		// 	terminateconnection(sockid);
		// 	break;
		// }
		// else
		// {
    
    while(size>0&&(n=recv(sockid,(char*)&chunk,sizeof(chunk),0))>0)
    {
		// text=decryption(msg.encmsg.encodedmessage);
		text=decryption(chunk);
		cout<<text<<"\n";

		fwrite(text,sizeof(char),1024,fp);
		// memset(msg.encmsg.encodedmessage,'\0',1024);
		size=size-n;
		memset(chunk,'\0',1024);

		// }
	}

	recv(sockid,(Msg*)&msg,sizeof(msg),0);
	
		cout<<msg.hdr.opcode<<"\n";
		terminateconnection(sockid);
	
	fclose(fp);
	//Recieverequest for terminati
	
}

void dhkeyexchange(int sockid)
{
	PubKey pkey;
	Msg msg;
	
	for(int i=0;i<3;i++)
	{
		//sending pub key to server
		computepubkey(pkey);
		msg.hdr.opcode=10;
		msg.pubkey=pkey;
		send(sockid,(Msg*)&msg,sizeof(msg),0);

		//recv public key of server
		recv(sockid,(Msg*)&msg,sizeof(msg),0);
		int y=msg.pubkey.y;

		long temp=power(y,x,q);
		key.push_back(temp);
	}
	showkeys();
}

int main()
{
	srand(time(0));
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

	dhkeyexchange(sockid);
	filetransfer(sockid);
}
