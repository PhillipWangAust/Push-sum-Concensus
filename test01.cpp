#include "agent.h"
#include "communication.h"
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
#include <time.h>
#include <unistd.h>
#include <thread>
using namespace std;

#define BUFSIZE 2048
#define BUFLEN 2048

const int numAgents = 2;
const int maxSteps = 100;
  // The agents are stored in a vector
  // The graph (neighbors) is stored in a vector of list
 // vector<Agent*> nodes(numAgents);
 // vector<AgentList> edges(numAgents);


myVector a,b,c,d,e;

int main()
{
  me->_id = 1; //this is node id 1;
  a.address = strdup("127.0.0.1");
  a.id = 2;
  b.address = strdup("10.1.10.5");
  b.id = 5;
  srand(1);
  //neighbors to send to
  me->sendNeighbor.push_back(a); //load neighbors
  //me->sendNeighbor.push_back(b); //load neighbors
  
  //neighbors to send keys to
  c.address = strdup("127.0.0.1");
  me->recvNeighbor.push_back(c);//load neighbors that need my key
  //me->recvNeighbor.push_back(d);//neighbors I receive from
  //printf("Initialize nodes long=%lu\n", sizeof(long));
  
  char id[32];
  double state;
  printf("neighbors: %d\n",me->neighbors );
  int myIndex = 0;
  thread t1(SetupServer);
  
       
      state = (rand() % 1000);
      me->setState(state);
      me->updateAlpha();

      me->s = state;
      me->w = 1;
      me->updateWeights();
      me->old_alpha = me->alpha;
     
  
  printf("Initialize edges\n");
   printf("Main loop\n");
  
	sleep(5); 
  
  for(int i=0;i<maxSteps;i++)
  {
      sleep(1);
      me->communicate();
       // cin>>id;
        //me->communicate();
        cout<<"My state is: " <<me->state<<endl;
  }
      fclose(me->fp);
        t1.detach();
        
  return 0;
}

