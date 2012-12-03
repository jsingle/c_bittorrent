#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h> //internet address library
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include <openssl/sha.h> //hashing pieces

#include "bencode.h"
#include "bt_lib.h"
#include "bt_setup.h"

int send_bitfield(int new_client_sockfd,bt_bitfield_t bfield){
  // TODO send bitfield
  bt_msg_t bitfield_msg;
  bitfield_msg.length = 1+bfield.size;
  bitfield_msg.bt_type = BT_BITFILED;
  bitfield_msg.payload.bitfiled = bfield;
  int sent = send(new_client_sockfd,&bitfield_msg,bitfield_msg.length,0);
  printf("Bitfield sent!\n");
  return sent;
}



int log_write(log_info * log){
  float ms;
  char time[10];
  int time_len;
  gettimeofday(&(log->cur_tv),NULL);
  ms = (log->cur_tv.tv_sec - log->start_tv.tv_sec)*1000;
  ms += (log->cur_tv.tv_usec - log->start_tv.tv_usec)/1000;
  time_len = snprintf(time,10,"%.2f ",ms);
  int fw = fwrite(time,time_len,1,log->log_file);
  fw = fwrite(log->logmsg,log->len,1,log->log_file);
  fflush(log->log_file);
  return fw;
}




void calc_id(char * ip, unsigned short port, char *id){
  char data[256];
  int len;

  //format print
  len = snprintf(data,256,"%s%u",ip,port);

  //id is just the SHA1 of the ip and port string
  //TODO uncomment this
  SHA1((unsigned char *) data, len, (unsigned char *) id); 

  return;
}

/*propogate a peer_t struct and add it to the bt_args structure*/
int add_peer(peer_t *peer, bt_args_t *bt_args, char * hostname, unsigned short port){
  //bt_args.peers[i] = peer;
  //peer-> hostname = inet_ntoa(peer->sockaddr.sin_addr),
  //peer->port;
  return 0;
}


int accept_new_peer(int incoming_sockfd, char * sha1, char * h_message, char * rh_message, int * newfd, log_info * log, peer_t * peer){
  //try to accept incoming connection from new peer 
  // Wait for a connection on the socket
  int client_fd;              // socket file descriptor
  struct sockaddr_in client_addr;

  socklen_t client_addr_len = sizeof(client_addr); 
  printf("Waiting for connection...\n");
  client_fd = accept(
      incoming_sockfd,//int socket, 
      (struct sockaddr *) &client_addr,//struct sockaddr * address, 
      &client_addr_len//socklent_t * address_len
      );

  if(client_fd == -1){
    perror("Accept New Peer Failed");
    log->len = snprintf(log->logmsg,100,"HANDSHAKE FAILED accept failed\n");
    log_write(log);

    return 1;
  }
  printf("Accepted connection...\n");
  //TODO: fix sha

  //SHA1(ti_name, strlen(ti_name), twenty); 

  char self_id[] = "1232";

  // Construct and read handshake
  bzero(h_message,H_MSG_LEN);
  h_message[0] = 19;
  strcpy(&(h_message[1]),"BitTorrent Protocol");
  memset(&(h_message[20]),0,8);
  memcpy(&(h_message[28]),sha1,20);
  memcpy(&(h_message[48]),self_id,20);

  int rh_ret = read_handshake(client_fd,rh_message,h_message);
  char * ip;
  int port;
  char id[21];
  ip = inet_ntoa(client_addr.sin_addr);
  port = htons(client_addr.sin_port);
  calc_id(ip,port,id);
  id[20] = '\0';

  if(rh_ret){   //read failed
    printf("READ HANDSHAKE failed\n");
    log->len = snprintf(log->logmsg,100,"HANDSHAKE FAILED peer:%s port:%d id:i%20s\n",
        ip,port,id);
    log_write(log);

    return 1;
  }

  // send handshake in response
  int sent = send(client_fd,h_message,H_MSG_LEN,0);
  if(sent != H_MSG_LEN){
    //should be 68...
    fprintf(stderr,"Handshake wasn't sent correctly, returned %d\n",sent);
    log->len = snprintf(log->logmsg,100,"HANDSHAKE SEND FAILED peer:%s port:%d id:%20s\n",
        ip,port,id);
    log_write(log);
    return 1;
  }   


  // Make a peer
  peer = malloc(sizeof(peer_t));

  printf("Attempting connection with peer %s on port %d\n",
      ip,
      port);


  init_peer(peer, id, ip, port);
  *newfd = client_fd;
  log->len = snprintf(log->logmsg,100,"HANDSHAKE SUCCESS peer:%s port:%d id:%20s\n",
      inet_ntoa(peer->sockaddr.sin_addr),peer->port,id);
  log_write(log);
  return 0;
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
  memcpy(&(h_message[28]),sha1,20);
  memcpy(&(h_message[48]),p->id,20);
  return;
}

