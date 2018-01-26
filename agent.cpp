/*
	Agent.cpp
*/
#include <math.h>
#include "agent.h"
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <chrono>
#include <unistd.h>
#define KEY_LENGTH 64
#define STATE_FACTOR 10000
#define ALPHA_FACTOR 10
#define SERVICE_PORT 21231
#define RESPONSE_PORT 21232
#define BUFSIZE 2048
#define BUFLEN 2048
#define NEIGHBORS 2
#define K 20
//#define ALPHA_RULE rand() % ALPHA_FACTOR + 1
using namespace std;
Agent::Agent(std::string _id)
  :id(_id),
   state(0.0),
   step(0),
   alpha(1),
   neighbors(1),
   long_state(0),
   diff_state(0)
{
  // Generate key pair
  paillier_keygen(KEY_LENGTH,
		  &pubKey,
		  &prvKey,
		  paillier_get_rand_devurandom);
      fp= fopen("plot.dat","w+");
      tm = fopen("timer.dat","w+");

  // Open the log file:
  logfile = fopen(id.append(".log").c_str(), "w");
  if (logfile == NULL)
    {
      printf("%s log open failed\n", id.c_str());
    }
  
  alpha = rand() % ALPHA_FACTOR + 1;
}

Agent::~Agent()
{
  // Close the log file
  if(logfile != NULL)
    fclose(logfile);

  // Destroy the key pair
  paillier_freepubkey(pubKey);
  paillier_freeprvkey(prvKey);
}

int Agent::communicate()
{
  
  paillier_plaintext_t* m_s;
  paillier_ciphertext_t* c_s;
  /*SET UP WIFI CONNECTIVITY*/
  struct sockaddr_in myaddr, remaddr;
  int fd, slen=sizeof(remaddr);
  char buf[BUFLEN];
    /* create a socket */
      
  if ((fd=socket(AF_INET, SOCK_DGRAM, 0))==-1)
      cout << "socket created\n" ;
  memset((char *)&myaddr, 0, sizeof(myaddr));
  myaddr.sin_family = AF_INET;
  myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  myaddr.sin_port = htons(0);
  if (bind(fd, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0)
   {
      cout << "bind failed";
      return 0;
    }    
  memset((char *) &remaddr, 0, sizeof(remaddr));
  remaddr.sin_family = AF_INET;
  remaddr.sin_port = htons(RESPONSE_PORT);
  
  /*SEND TO ALL NEIGHBORS*/

  for(int j=0;j<sendNeighbor.size();j++)
  {
     auto start = std::chrono::high_resolution_clock::now();

    /* multiply state by weight of ith node*/
    long_state = (long) lround(s * STATE_FACTOR* sendNeighbor[j].weight_s); //state*s
    //cout<<" my weight "<<long_state<<" w: "<<w<<" weight_s: "<<weight_s<<endl;
    //cout<<" my weight "<<long_state<<" w: "<<w<<" weight_w: "<<weight_w<<endl;
    //cout<<"Long_state: "<<long_state<<" s: "<<s<<" weight_s: "<<sendNeighbor[j].weight_s<<endl;
    m_s = paillier_plaintext_from_ui(long_state);
    c_s = NULL;
    //cout<<"here is am: "<<sendNeighbor[j]._pubKey<<endl;
    c_s = paillier_enc(NULL, sendNeighbor[j]._pubKey, m_s, //encrypt state*statefactor *weight_s as c_s
         paillier_get_rand_devurandom);

    char* byteCtxt = (char*)paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2, c_s);//serialize cypher
    int s_ctxt = PAILLIER_BITS_TO_BYTES(pubKey->bits)*2;
    int i=0;
    char sendBuf[BUFSIZE];
    int type = 2;
    memcpy(&sendBuf[i],&type,sizeof(int)); i+=sizeof(int); //add type
    memcpy(&sendBuf[i],&step,sizeof(int)); i+=sizeof(int); //add step index;
    memcpy(&sendBuf[i],&s_ctxt,sizeof(int)); i+=sizeof(int); //add size of cypher text
    for(int k=i;k<i+s_ctxt;k++) //add encrypted state* statefactor * weight_s
    {
      sendBuf[k] = byteCtxt[k-i];
    }
      i+=s_ctxt;
    long_state = (long) lround(w * STATE_FACTOR* sendNeighbor[j].weight_w);
    //cout<<"Long_state: "<<long_state<<" w: "<<w<<" weight_w: "<<sendNeighbor[j].weight_w<<endl;
    m_s = paillier_plaintext_from_ui(long_state);
    c_s = NULL;
    c_s = paillier_enc(NULL, sendNeighbor[j]._pubKey, m_s, //encrypt state*statefactor *weight as c_s
         paillier_get_rand_devurandom);

    byteCtxt = (char*)paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2, c_s);//serialize cypher
    for(int k=i;k<i+s_ctxt;k++)// add encrypted state * statefactor * weight_w
    {
      sendBuf[k] = byteCtxt[k-i];
    }
      i+=s_ctxt;

        
    if (inet_aton(sendNeighbor[j].address, &remaddr.sin_addr)==0) 
    {
      cout << "inet_aton() failed\n";
      exit(1);
    }
    auto finish = std::chrono::high_resolution_clock::now();
    int k=0;
    if (sendto(fd, sendBuf, i, 0, (struct sockaddr *)&remaddr, slen)==-1)
      cout << "Error at sendto";
    usleep(100);   
    std::chrono::duration<double> elapsed = finish - start;
    fprintf(tm , " %.5f\n ", elapsed.count());
  }

	close(fd);
  paillier_freeplaintext(m_s);
  paillier_freeciphertext(c_s);
  
  return 0;
}
int Agent::send_key()
{
    char* hexPubKey = paillier_pubkey_to_hex(pubKey); //serialize pub key
    int count = 3;//send is one, this is a key transfer
    int s_pub = strlen(hexPubKey);
     int i=0;
    char type[sizeof(int)];
    memcpy(&type,&count,sizeof(int));
    char sendBuf[BUFSIZE];
    memcpy(&sendBuf[i],&type,sizeof(int)); i+=sizeof(int); //add type
    memcpy(&sendBuf[i],&_id,sizeof(int)); i+=sizeof(int); //add id of node
    memcpy(&sendBuf[i],&s_pub,sizeof(int)); i+=sizeof(int); //add size of public key 
    strcpy(&sendBuf[i],hexPubKey);i+=s_pub; //add the public key
     struct sockaddr_in myaddr, remaddr;
    int fd, slen=sizeof(remaddr);
    /* create a socket */   
    if ((fd=socket(AF_INET, SOCK_DGRAM, 0))==-1)
      cout << "socket created\n" ;
    memset((char *)&myaddr, 0, sizeof(myaddr));
    myaddr.sin_family = AF_INET;
    myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    myaddr.sin_port = htons(0);
    if (bind(fd, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) 
    {
        cout << "bind failed";
        return 0;
    }    
    memset((char *) &remaddr, 0, sizeof(remaddr));
    remaddr.sin_family = AF_INET;
    remaddr.sin_port = htons(RESPONSE_PORT);

    for(int a =0;a<recvNeighbor.size();a++) //send to all neighbors
    {
    
      if (inet_aton(recvNeighbor[a].address, &remaddr.sin_addr)==0) 
      {
        cout << "inet_aton() failed\n";
        exit(1);
      }
      int k=0;
      if (sendto(fd, sendBuf, i, 0, (struct sockaddr *)&remaddr, slen)==-1)
        cout << "Error at sendto";
      usleep(1000);
  }
  
  close(fd);
 
  return 0;
}

double Agent::setState(const double st)
{
  state = st;
  old_state = state;
  alpha = updateAlpha();
  old_alpha = alpha;
  logState();
  _states.push_back(state);
  _alphas.push_back(alpha);
  step++;
  return state;
}
double Agent::setDiff(const double diff)
{
  diff_state = diff;
}
int Agent::updateState()
{
  /*
    > convert diff_state to double
    > and add to state 
    > change alpha
    > log the state
  */
  
  
  old_state = state;
  fprintf(fp,"%d %.3f %3f %3f\n",step, s, w, (s/w));
  double _sum_w=0,_sum_s=0;
  for(int i=0;i<recvNeighbor.size();i++)
  {
    _sum_s += recvNeighbor[i].sum_s;
    _sum_w += recvNeighbor[i].sum_w;
  }
  _sum_s+= s*weight_s*STATE_FACTOR;
  _sum_w+= w*weight_w*STATE_FACTOR;
  s = _sum_s/(double)STATE_FACTOR;
  w = _sum_w/(double)STATE_FACTOR;
  step++;
  logState();
cout<<"Update, S: "<<s<<" and W: "<<w<<" ratio: "<<(double)s/(double)w<<" step is: "<<step<<endl;
  return 0;
}

int Agent::logState()
{
  fprintf(logfile, "%8.4lf\t%2ld\t%ld\n", state, alpha, diff_state);
  
}


/*
  This function is called by another Agent 
 */
int Agent::exchange(paillier_pubkey_t* pub,
		    paillier_ciphertext_t* msg_in,
		    paillier_ciphertext_t* msg_out,int a, int step)
{
    paillier_plaintext_t* m_a;
	cout<<"Respond with state: "<<_states[step-1]<<endl;
      long_state = (long) lround(_states[step-1] * STATE_FACTOR);
      m_a = paillier_plaintext_from_ui(_alphas[step-1]);
      
    

  // encrypt the state
  paillier_plaintext_t* m_s = paillier_plaintext_from_ui(long_state);
 
  
  paillier_ciphertext_t* c_s = NULL;
  c_s = paillier_enc(NULL, pub, m_s,
		     paillier_get_rand_devurandom);

  paillier_ciphertext_t* c_d = paillier_create_enc_zero();

  // c_d = ENC( x_j + (-x_i) )
  paillier_mul(pub, c_d, msg_in, c_s);

  if (msg_out == NULL)
    msg_out = paillier_create_enc_zero();
  
  // msg_out = ENC( alpha * (x_j + (-x_i) )
  paillier_exp(pub, msg_out, c_d, m_a);


  paillier_freeplaintext(m_s);
  paillier_freeplaintext(m_a);
  paillier_freeciphertext(c_s);
  paillier_freeciphertext(c_d);
  return 0;
}

long Agent::ciphertext_to_long(paillier_ciphertext_t* c)
{
  paillier_plaintext_t* m = paillier_dec(NULL, pubKey, prvKey, c);

  size_t nBytes = 0;
  unsigned char* bytes = (unsigned char*) mpz_export(0, &nBytes, 1, 1, 0, 0, m->m);

  long int e = 0;
  //  assert( nBytes > sizeof(a));
  //  for(int i=nBytes-1; i >= nBytes-sizeof(a); --i)
  for(int i= 0; i < nBytes; i++)
  {
      e = (e << 8) | bytes[i];
  }

  paillier_freeplaintext(m);
  free(bytes);
  return e;
}

long Agent::updateAlpha()
{
  return rand() % ALPHA_FACTOR + 1;
  //  return ALPHA_FACTOR;
  //return alpha;
}
void Agent::updateWeights()
{
    double temp = 0;
    double sum_s = 0;
    double sum_w = 0;
    for(int i=0;i<sendNeighbor.size();i++)
    {
      sendNeighbor[i].weight_s = rand()%ALPHA_FACTOR;
      sum_s += sendNeighbor[i].weight_s;
      sendNeighbor[i].weight_w = rand()%ALPHA_FACTOR;
      sum_w += sendNeighbor[i].weight_w;
    }
    weight_w = rand()%ALPHA_FACTOR;
    sum_w += weight_w;
    weight_s = rand()%ALPHA_FACTOR;
    sum_s += weight_s;
    for (int i=0;i<sendNeighbor.size();i++)
    {
      sendNeighbor[i].weight_s = sendNeighbor[i].weight_s/sum_s;
      sendNeighbor[i].weight_w = sendNeighbor[i].weight_w/sum_w;
      if(step > K)
      {
        sendNeighbor[i].weight_w = sendNeighbor[i].weight_s;
      }
      temp += sendNeighbor[i].weight_s;
    }
    weight_w = weight_w/sum_w;
    weight_s = weight_s/sum_s;
    if(step > K)
    {
      cout <<"Step is > 20"<<endl;
      weight_w = weight_s;
    }
    temp += weight_s;
    cout<<"s: "<<s<<" weights_s: "<<weight_s<<" w: "<<w<<" weights_w: "<<weight_w<<" sum: "<<temp<<endl;
    

  

  
}
