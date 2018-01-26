#include "agent.h"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <list>
#include <iostream>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <thread>
#define BUFSIZE 2048
#define BUFLEN 2048
#define SERVICE_PORT 21231
#define RESPONSE_PORT 21232
#define NEIGHBORS 2
using namespace std;
extern Agent *me = new Agent(string("node1"));

int SetupServer()
{
	char *read;
  	int recIndex;
  	double recState;
  	double recAlpha;
	struct sockaddr_in myaddr;	/* our address */
	struct sockaddr_in remaddr;	/* remote address */
	socklen_t addrlen = sizeof(remaddr);		/* length of addresses */
	int recvlen;			/* # bytes received */
	int fd;				/* our socket */
	char buf[BUFSIZE];
	bzero(buf,BUFSIZE);
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
    {
		cout << "cannot create socket\n";
		return 0;
	}
    memset((char *)&myaddr, 0, sizeof(myaddr));
	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	myaddr.sin_port = htons(SERVICE_PORT);
    if (bind(fd, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) 
    {
		cout <<"bind failed";
		return 0;
	}
	int index;
	int _step;
	char respIp[addrlen];
    for (;;) 
    {
		recvlen = recvfrom(fd, buf, BUFSIZE, 0, (struct sockaddr *)&remaddr, &addrlen);
		if (recvlen > 0) 
		{
			inet_ntop(AF_INET, &(remaddr.sin_addr),respIp, addrlen);
			cout<<"Received from addr: "<<respIp<<endl;

			for(int a=0;a<me->recvNeighbor.size();a++)
			{
				
				if(strcmp(me->recvNeighbor[a].address, respIp) == 0)
				{
					index = a; //what neighbor is this
					
				}
				
			}
		
			paillier_pubkey_t* _pubKey;
	 		paillier_ciphertext_t* ctxt_s;
	 		paillier_ciphertext_t* ctxt_w;
	 		char hexPubKey[BUFSIZE]; bzero(hexPubKey,BUFSIZE);
	 		char byteCtxt_s[BUFSIZE];bzero(byteCtxt_s,BUFSIZE);
	 		char byteCtxt_w[BUFSIZE];bzero(byteCtxt_w,BUFSIZE);
			
	 		int def=0,s_ctxt,s_pub;
			int i=0;
			int trigger = 0;
			memcpy(&def,&buf[i],sizeof(int)); i+=sizeof(int); //read type	
			if(def == 2)//this is a response
			{
				trigger++;
				memcpy(&_step, &buf[i],sizeof(int));i+=sizeof(int);//read step index;
				memcpy(&s_ctxt,&buf[i],sizeof(int));i+=sizeof(int);//read size					
				memcpy(&byteCtxt_s, &buf[i],s_ctxt); i+=s_ctxt; //read cypher state*statefactor*weight_s
				memcpy(&byteCtxt_w, &buf[i],s_ctxt); i+=s_ctxt; //read cypher state*statefactor*weight_w											
				ctxt_s = paillier_ciphertext_from_bytes((void*)byteCtxt_s, PAILLIER_BITS_TO_BYTES(me->pubKey->bits)*2); //recreate
				ctxt_w = paillier_ciphertext_from_bytes((void*)byteCtxt_w, PAILLIER_BITS_TO_BYTES(me->pubKey->bits)*2); //recreate
				int cont = 1;
				long result_s =0, result_w = 0;
				me->diff_state =0;
				result_s = me->ciphertext_to_long(ctxt_s);
				result_w = me->ciphertext_to_long(ctxt_w);

				if (trigger==1)
				{
					cout<<"sending response"<<endl;
					//me->communicate();
				}
				//cout<<"received _s "<<result_s<<" received _w " <<result_w<<endl;
				if(me->recvNeighbor[index].step <= _step)
				{						
                    me->recvNeighbor[index].step = _step;
                    me->recvNeighbor[index].sum_s = result_s;
                    me->recvNeighbor[index].sum_w = result_w;
                }
                for(int c=0;c<me->recvNeighbor.size();c++)
                {
                    if(me->recvNeighbor[c].step == _step)
                    {
                        cont *= 1;
                    }
                    else
                    {
                        cont *= 0;
                    }
                }

                if(cont)
                {
                    /*for(int c=0;c<me->neighbors;c++)
                    {
                        me->sum_s+=me->recvNeighbor[c].result_s;
                        me->sum_w+=me->recvNeighbor[c].result_w;

                    }*/
                    trigger = 0;
                    me->updateState();
                    me->updateWeights();
                }
			}
			else
			{
				
				printf("received key share\n");
				memcpy(&_step, &buf[i],sizeof(int));i+=sizeof(int);//read node id;
				memcpy(&s_pub,&buf[i],sizeof(int)); i+=sizeof(int); //read size of public key						 
				memcpy(&hexPubKey,&buf[i],s_pub); i+=s_pub; //read public key

						//cout<<"pubkey: "<<hexPubKey<<endl;
				_pubKey = paillier_pubkey_from_hex(hexPubKey); //recreate public key
				bool found = 0;
				for(int k=0;k<me->sendNeighbor.size();k++)
				{
					if(me->sendNeighbor[k].id == _step)
					{
						found = 1;
						me->sendNeighbor[k]._pubKey = _pubKey;
					}
				}
				printf("received key stored\n");
				cout<<"sending keys"<<endl;
				me->send_key();
						
			}		
						//increment that I have received a response
					
		}

		bzero(buf,BUFSIZE);
			
		
	}
}

