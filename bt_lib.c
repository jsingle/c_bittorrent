#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h> //internet address library
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <sys/stat.h>
#include <arpa/inet.h>

#include <openssl/sha.h> //hashing pieces

#include "bencode.h"
#include "bt_lib.h"
#include "bt_setup.h"



void calc_id(char * ip, unsigned short port, char *id){
  char data[256];
  int len;

  //format print
  len = snprintf(data,256,"%s%u",ip,port);

  //id is just the SHA1 of the ip and port string
  //TODO uncomment this
  //SHA1((unsigned char *) data, len, (unsigned char *) id); 

  return;
}

/*propogate a peer_t struct and add it to the bt_args structure*/
int add_peer(peer_t *peer, bt_args_t *bt_args, char * hostname, unsigned short port){
  //bt_args.peers[i] = peer;
  //peer-> hostname = inet_ntoa(peer->sockaddr.sin_addr),
  //peer->port;
  return 0;
}


int accept_new_peer(int incoming_sockfd, char * sha1, char * h_message, char * rh_message){
  //try to accept incoming connection from new peer 
  // Wait for a connection on the socket
  int client_fd;              // socket file descriptor
  struct sockaddr_in client_addr;

  socklen_t client_addr_len; 
  printf("Waiting for connection...\n");
  client_fd = accept(
      incoming_sockfd,//int socket, 
      (struct sockaddr_in *) &client_addr,//struct sockaddr * address, 
      &client_addr_len//socklent_t * address_len
      );

  printf("Accepted connection...\n");
  //TODO: fix sha

  //SHA1(ti_name, strlen(ti_name), twenty); 

  char self_id[] = "1232";

  // Construct and read handshake
  bzero(h_message,H_MSG_LEN);
  h_message[0] = 19;
  strcpy(&(h_message[1]),"BitTorrent Protocol");
  memset(&(h_message[20]),0,8);
  memcpy(sha1,&(h_message[28]),20);
  memcpy(self_id,&(h_message[48]),20);

  if(read_handshake(client_fd,rh_message,h_message)){
    printf("READ HANDSHAKE failed\n"); 
  }

  // send handshake in response
  int sent = send(client_fd,h_message,H_MSG_LEN,0);
  if(sent != H_MSG_LEN){
    //should be 68...
    fprintf(stderr,"Handshake wasn't sent correctly, returned %d\n",sent);
  }   


  // Make a peer
  peer_t * peer;
  peer = malloc(sizeof(peer_t));
 
  char id[20];
  char* ip = inet_ntoa(client_addr.sin_addr);
  int port = htons(client_addr.sin_port);

  printf("Attempting connection with peer %s on port %d\n",
      ip,
      port);

  //calculate the id, value placed in id
  calc_id(ip,port,id);

  init_peer(peer, id, ip, port);
  
  return client_fd;
}

/**
 * init_peer(peer_t * peer, int id, char * ip, unsigned short port) -> int
 *
 *
 * initialize the peer_t structure peer with an id, ip address, and a
 * port. Further, it will set up the sockaddr such that a socket
 * connection can be more easily established.
 *
 * Return: 0 on success, negative values on failure. Will exit on bad
 * ip address.
 *   
 **/
int init_peer(peer_t *peer, char * id, char * ip, unsigned short port){

  struct hostent * hostinfo;
  //set the host id and port for referece
  memcpy(peer->id, id, ID_SIZE);
  peer->port = port;

  //get the host by name
  if((hostinfo = gethostbyname(ip)) ==  NULL){
    perror("gethostbyname failure, no such host?");
    herror("gethostbyname");
    exit(1);
  }

  //zero out the sock address
  bzero(&(peer->sockaddr), sizeof(peer->sockaddr));

  //set the family to AF_INET, i.e., Iternet Addressing
  peer->sockaddr.sin_family = AF_INET;

  //copy the address to the right place
  bcopy((char *) (hostinfo->h_addr), 
      (char *) &(peer->sockaddr.sin_addr.s_addr),
      hostinfo->h_length);

  //encode the port
  peer->sockaddr.sin_port = htons(port);

  return 0;

}

/**
 * print_peer(peer_t *peer) -> void
 *
 * print out debug info of a peer
 *
 **/
void print_peer(peer_t *peer){
  int i;

  if(peer){
    printf("peer: %s:%u ",
	inet_ntoa(peer->sockaddr.sin_addr),
	peer->port);
    printf("id: ");
    for(i=0;i<ID_SIZE;i++){
      printf("%02x",peer->id[i]);
    }
    printf("\n");
  }
}



/**
 *
 * return pointer to location of handshake message
 */
void get_peer_handshake(peer_t * p, char * sha1 , char * h_message){
  h_message[0] = 19;
  strcpy(&(h_message[1]),"BitTorrent Protocol");
  memset(&(h_message[20]),0,8);
  memcpy(sha1,&(h_message[28]),20);
  memcpy(p->id,&(h_message[48]),20);
  return;
}

