#ifndef MYRESOLVER_H_INCLUDE
#define MYRESOLVER_H_INCLUDE


#define DNS_PORT        53

#define ROOT_SERVER_0   "198.41.0.4"
#define ROOT_SERVER_1   "192.228.79.201"
#define ROOT_SERVER_2   "192.33.4.12"
#define ROOT_SERVER_3   "199,7,91,13"
#define ROOT_SERVER_4   "192.203.230.10"

#include <iostream>
#include <vector>
#include <string.h>
#include <sys/types.h>
#include <cstring> // memcopy

using std::string;
using std::vector;


/****************************************************
*Packet structure:
*****************************************************/

/****************************************************
* DNS HEADER PACKET
*****************************************************/
typedef struct header {
  //random 16 bit number
  unsigned short ID;
  
  unsigned char RD: 1;      //1 bit field -- (Pursue query recursively. One for yes)
  unsigned char TC: 1;      //1 bit field -- (Truncation. Used in response)
  unsigned char AA: 1;      //1 bit field --(Used in responses to say if answer is authoritative)
  unsigned char Opcode: 4;  //4 bit field. (Should be 0 which representing standard query)
  unsigned char QR: 1;      //1 bit field --(0 for query, 1 for response)
    
  unsigned char RCODE : 4;  //4 bit field -- (Response code)
  unsigned char CD : 1;     //checking disabled
  unsigned char AD : 1;     //authenticated data
  unsigned char Z: 1;       //3 bit field -- (Unimportant. Set to 0)
  unsigned char RA: 1;      //1 bit field -- (In response. Says if server can pursue recursively)
  
  
  
  
  /************************************************
  ******************RCODE FIELDS*******************
  *4 bits. Response code
  *0 No error condition
  *1 Format error - The name server was unable to interpret the query.3 
  *2 Server failure - The name server was unable to process this query due to a problem with
  *the name server.
  *3 Name Error - Meaningful only for responses from an authoritative name server, this code
  *signifies that the domain name referenced in the query does not exist.
  *4 Not Implemented - The name server does not support the requested kind of query.
  *5 Refused - The name server refuses to perform the specified operation for policy reasons.
  ************************************************/
  
  //16bits. Number of entries in question section. Set to 1, indicating we have one quesiton
  unsigned short QDCOUNT;
  
  //16 bits. Number of records in answer section. We set to 0. We have no answers.
  unsigned short ANCOUNT;
  
  //16 bits. Number of name server resource records. We set to 0. Don't have to worry about in resonse
  unsigned short NSCOUNT;
  
  //16 bits. Number of records in other sections. We set to 0. Don't have to worry about in response
  unsigned short ARCOUNT;
  
} DNSHeader;
/****************************************************
* DNS QUESTION PACKET
*****************************************************/
typedef struct question {  
  //Specifies type of query A or AAAA. 
  unsigned short QTYPE;
  //possible values:
  // A          = 0x0001 (1)
  // AAAA       = 0x1100 (28)
  // CNAME      = 0x0005 (5)
  //name servers= 0x0002 (2)
  //mail servers= 0x000f (15)
 
  //Specifies class of query. Will be internet most of time. 0x0001
  unsigned short QCLASS;

}  DNSQuestion;

/****************************************************
* DNS RESOURCE RECORD PACKET
*****************************************************/
// #pragma pack(push,1)
typedef struct {
   
  unsigned short TYPE;//What type. A or AAAA or CNAME
  unsigned short CLASS;//Specifies class of query. Should be internet
  unsigned int TTL;  //how long the query lasts
  unsigned short RDLENGTH;  //How long the RDATA field is

} R_DATA;
// #pragma pack(pop)

typedef struct resRec
{
  unsigned char *name;
  R_DATA *resource;
  unsigned char *rdata; //cname 

}DNS_ResRec;

typedef struct addSection
{
  unsigned char Name:8; // 1 byte
  unsigned short Type:16; //2 bytes
  unsigned short payloadSize:16; //2 bytes
  unsigned char higher_bits:8; // 1 byte
  unsigned char EDNS0_v:8; // 1 byte
  unsigned short z:8; // 2 bytes
  unsigned short length:16; //2 bytes 


}DNS_RRSIG_Request;

/****************************************************
* DNS QUERY PACKET
*****************************************************/
struct query
{
  unsigned char *name;
  DNSQuestion *ques;

} DNSQuery;





/**Function Declarations**/
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host);
char* ReadIPv4Address(unsigned char* reader,unsigned char*buffer, int*count);
char* ReadIPv6Address(unsigned char* reader,unsigned char*buffer, int*count);
unsigned char* ReadName(unsigned char* reader,unsigned char* buffer,int* count);

void printDNSHeader(DNSHeader *header);



/****************************************************
* MY RESOLVER CLASS 
*****************************************************/
class MyResolver
{
public:
  /*declorations*/

  /*fields*/
  string ipType;
  string URL;
  int packetCount;
  /*methods*/
  void myResolver();
  void getDNSAddresses();
  string findIP();
  vector<unsigned int> createIPVector(unsigned int a, unsigned int b, unsigned int c, unsigned int d);
  void readPacket(unsigned char* buffer, DNSHeader *dns, unsigned char* qname);
  void sendPacket(const char * destAddress);


private:
  vector<std::vector<unsigned int> > DNSAddresses;
  std::vector<string> DNSRootAddr; // contains string format of the root servers 
};

#endif //MYRESOLVER_H_INCLUDE
