#include <stdlib.h>
#include <stdio.h>
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

#include <stdarg.h> // for our logging function

#include "bencode.h"
#include "bt_lib.h"
#include "bt_setup.h"

extern log_info logger;
extern bt_args_t bt_args;

// fd2peerpos: gets the peer position of a peer
int fd2peerpos(int i){
  int peerpos,j;

  peerpos=-1;
  for(j=0;j<MAX_CONNECTIONS;j++){
    if(bt_args.sockets[j] == i && bt_args.peers[j] != NULL){
      peerpos=j;
      break;
    }
  }

  if(peerpos==-1){
    fprintf(stderr,"Couldn't find connected peer in peers\n");
    exit(1);
  }

  return peerpos;
}


// setup_fds_for_polling: add active peer fd to read list
void setup_fds_for_polling(int * incoming_fd,int * maxfd){
  int i;
  // Initialize a port to listen for incoming connections
  *incoming_fd = init_incoming_socket(bt_args.port); 
  
  // initialize polling set
  FD_ZERO(&(bt_args.readset));
  FD_SET(*incoming_fd, &(bt_args.readset));
  *maxfd = *incoming_fd;
  
  for(i=0; i<MAX_CONNECTIONS;i++){
    if (bt_args.peers[i] != NULL){
      FD_SET(bt_args.sockets[i], &(bt_args.readset)); // add to master set
      if (bt_args.sockets[i] > *maxfd) { // keep track of the maxfd
        *maxfd = bt_args.sockets[i];
      }
    }
  }
}


// Prints info about how many pieces of a file we have
void test_progress(piece_tracker * piece_track,bt_info_t * tracker_info){
  int i;
  int havepieces=0;
  int contig=-1;
  printf("File bitfield: ");
  for(i=0;i<tracker_info->num_pieces;i++){
    unsigned char bitand = 0x80;
    if(piece_track->bitfield[i/8] & bitand>>(i%8)){
      //if(!havepieces) printf("Have pieces: %d",i);
      //else printf(", %d",i);
      printf("1");
      havepieces++;
    }
    else{
      printf("0");
      if (contig == -1) contig = i;
    }
  }
  if(havepieces)printf("\n");
  printf("Have %d of %d pieces, download %d%% completed, the %d first pieces are done\n",
      havepieces,tracker_info->num_pieces,(int)(100*havepieces)/tracker_info->num_pieces,contig);
  if(havepieces == tracker_info->num_pieces)
    printf("Download Complete!\n");
}

// Sends a request for a piece of a file
int send_request(int fd, bt_request_t * btrequest){
  bt_msg_t bitfield_msg;
  bitfield_msg.length = 1+3 +sizeof(bt_request_t);
  bitfield_msg.bt_type = BT_REQUEST;
  memcpy(&(bitfield_msg.payload.request),btrequest, sizeof(bt_request_t));

  int sent = send(fd,&bitfield_msg,bitfield_msg.length + sizeof(int),0);
  if(sent == bitfield_msg.length + sizeof(int)){
    return 0;
  }
  else{
    log_record("error in send request, returned: %d\n",sent);
    return 1;
  }
}

// Sends a message about if we're interested or not in a file
int send_interested(int fd, int interested){
  bt_msg_t bitfield_msg;
  bitfield_msg.length = 1;
  if(interested)
    bitfield_msg.bt_type = BT_INTERSTED;
  else
    bitfield_msg.bt_type = BT_NOT_INTERESTED;
  int sent = send(fd,&bitfield_msg,bitfield_msg.length + sizeof(int),0);
  if(sent == bitfield_msg.length + sizeof(int))
    return 0;
  else{
    log_record("error in send interested: %d\n",sent);
    return 1;
  }
}


//determine if interested in a peer, send appropriate interested msg
//returns 1 on interested
//      0 on not interested
int is_interested(piece_tracker * piecetrack, 
    peer_t *  peer, int fd){
  int i,j;
  int sent;
  for(i=0;i<piecetrack->size;i++){
    unsigned char a = 0x80;
    for(j=0;j<8;j++){
      if(!(piecetrack->bitfield[i] & a) && (peer->btfield[i] & a)){
        sent = send_interested(fd,1);//interested
        if(sent){
          log_record("MESSAGE: INTERESTED TO peer:%s FAILED\n",
              peer->id);
        }
        else{
          log_record("MESSAGE: INTERESTED TO peer:%s\n",
              peer->id);
        }
        peer->interested = 1;
        return 1;
      }
      a = a>>1;
    }
  }

  sent = send_interested(fd,0);//not interested
  if(sent){
    log_record("MESSAGE: NOT INTERESTED TO peer:%s FAILED\n",
        peer->id);
  }
  else{
    log_record("MESSAGE: NOT INTERESTED TO peer:%s\n",
        peer->id);
  }
  peer->interested = 0;
  return 0;
}



//process bitfields of peers and calls appropriate send_request
//returns:
//      0 - request send success
//      1 - request send fail
//      2 - couldn't find piece to request for
int process_bitfield(piece_tracker * piecetrack, peer_t *  peer, int fd){
  int i,j;
  bt_request_t btrequest;
  int sent;
  for(i=0;i<piecetrack->size;i++){

    unsigned char a = 0x80;
    for(j=0;j<8;j++){
      unsigned long int index = 8*i+j;
      if(!(piecetrack->bitfield[i] & a) && (peer->btfield[i] & a)){

        //TODO: mabye choose a random section to request, not go serially?

        btrequest.begin = piecetrack->recvd_pos[index];
        btrequest.index = index;
        if(piecetrack->recv_size < (piecetrack->piece_size
              - piecetrack->recvd_pos[index])){
          btrequest.length = (int)piecetrack->recv_size;
        }
        else{
          btrequest.length=piecetrack->piece_size-piecetrack->recvd_pos[index];
        }

        //deal with last piece scenario
        if(index==piecetrack->last_piece){
          if(btrequest.length+btrequest.begin > piecetrack->lp_size)
            btrequest.length = piecetrack->lp_size-btrequest.begin;
        }

        sent = send_request(fd,&btrequest);
        if(sent){
          log_record("MESSAGE: REQUEST TO peer:%s index:%i FAILED\n",
              peer->id,(int)index);
        }else{
          log_record("MESSAGE: REQUEST TO peer:%s index:%i begin:%i len:%i\n",
              peer->id,(int)index,btrequest.begin,btrequest.length);
        }
        return sent;
      }
      a = a>>1;
    }
  }
  sent = send_interested(fd,0);//not interested
  if(sent){
    log_record("MESSAGE: NOT INTERESTED TO peer:%s FAILED\n",
        peer->id);
  }
  else{
    log_record("MESSAGE: NOT INTERESTED TO peer:%s\n",
        peer->id);
  }
  peer->interested = 0;
  return 2;
}

// Sends a message about whether we have a piece or not
int send_have(int fd, int have){
  bt_msg_t bitfield_msg;
  bitfield_msg.length = sizeof(int) + 1;
  bitfield_msg.bt_type = BT_HAVE;
  bitfield_msg.payload.have = have;
  int sent = send(fd,&bitfield_msg,bitfield_msg.length + sizeof(int),0);
  //printf("Have %d sent!\n",bitfield_msg.payload.have);
  return sent;
}

// send a bitfield message
int send_bitfield(
    int new_client_sockfd,
    piece_tracker * piece_track,
    peer_t * peer )
{
  bt_msg_t * bitfield_msg = (bt_msg_t *)(piece_track->msg);
  bitfield_msg->bt_type = BT_BITFILED;
  bitfield_msg->length =  1 + sizeof(size_t) +3 + piece_track->size;
  bitfield_msg->payload.bitfiled.size = (size_t)piece_track->size;

  /*
     printf("msg:%d type:%d length:%d bfiled:%d\n",
     bitfield_msg,&(bitfield_msg->bt_type),&(bitfield_msg->length),
     &(bitfield_msg->payload.bitfiled));
     printf("bf: pt:%d send:%d\n",
     piece_track->bitfield,bitfield_msg->payload.bitfiled.bitfield);


     printf("sending bitfield: %c\n",piece_track->bitfield[0]);
     printf("sending bitfield: %c\n",bitfield_msg->payload.bitfiled.bitfield[0]);
     */


  int sent = send(new_client_sockfd,bitfield_msg,
      sizeof(int) + bitfield_msg->length,0);
  //printf("Bitfield sent!  Msg len: %3d, Sent Size %3d\n",
  //    bitfield_msg->length,sent);

  if(sent == sizeof(int) + bitfield_msg->length){
    log_record("MESSAGE: BITFIELD TO peer:%s bfield:%s\n",
        peer->id,piece_track->bitfield);
  }else{
    log_record("MESSAGE: BITFIELD to peer:%s FAILED\n",peer->id);
  }
  return sent;

}

// overides a 
void log_record( const char* format, ... ) {
  float ms;
  gettimeofday(&(logger.cur_tv),NULL);

  ms = (logger.cur_tv.tv_sec - logger.start_tv.tv_sec)*1000;
  ms += ((float)logger.cur_tv.tv_usec - (float)logger.start_tv.tv_usec)/1000;

  va_list args;
  fprintf(logger.log_file,"[%6.2f]  ",ms);//,time_len,1,log->log_file);
  va_start( args, format );
  vfprintf( logger.log_file, format, args );
  va_end( args );
  fprintf(logger.log_file, "\n" );

  fflush(logger.log_file);
}

void calc_id(char * ip, unsigned short port, char *id){
  char data[256];
  int len;

  //format print
  len = snprintf(data,256,"%s%u",ip,port);

  //id is just the SHA1 of the ip and port string
  SHA1((unsigned char *) data, len, (unsigned char *) id); 

  return;
}

/*propogate a peer_t struct and add it to the bt_args structure*/
int add_peer(peer_t *peer, char * hostname, unsigned short port){
  //bt_args.peers[i] = peer;
  //peer-> hostname = inet_ntoa(peer->sockaddr.sin_addr),
  //peer->port;
  return 0;
}


int accept_new_peer(int incoming_sockfd, char * sha1, char * h_message, char * rh_message, int * newfd, peer_t * peer){
  //try to accept incoming connection from new peer 
  // Wait for a connection on the socket
  int client_fd;              // socket file descriptor
  struct sockaddr_in client_addr;

  socklen_t client_addr_len = sizeof(client_addr); 
  
 // printf("Waiting for connection...\n");
  client_fd = accept(
      incoming_sockfd,//int socket, 
      (struct sockaddr *) &client_addr,//struct sockaddr * address, 
      &client_addr_len//socklent_t * address_len
      );

  if(client_fd == -1){
    perror("Accept New Peer Failed");

    log_record("HANDSHAKE FAILED accept failed\n");


    return 1;
  }
  //printf("Accepted connection...\n");


  // Construct and read handshake
  bzero(h_message,H_MSG_LEN);
  h_message[0] = 19;
  strcpy(&(h_message[1]),"BitTorrent Protocol");
  memset(&(h_message[20]),0,8);
  memcpy(&(h_message[28]),sha1,20);
  char * ip;
  unsigned short port;
  char id[21];
  ip = inet_ntoa(client_addr.sin_addr);
  port = htons(client_addr.sin_port);
  calc_id(ip,port,id);
  id[20] = '\0';
  memcpy(&(h_message[48]),id,20);

  printf("incoming port: %d\n",port);
  int rh_ret = read_handshake(client_fd,rh_message,h_message);

  memcpy(&(h_message[48]),bt_args.myid,20);
  if(rh_ret){   //read failed
    //printf("READ HANDSHAKE failed\n");
    log_record("HANDSHAKE FAILED peer:%s port:%d id:%X\n",
        ip,port,id);
    return 1;
  }

  // send handshake in response
  int sent = send(client_fd,h_message,H_MSG_LEN,0);
  if(sent != H_MSG_LEN){
    //should be 68...
    //fprintf(stderr,"Handshake wasn't sent correctly, returned %d\n",sent);
    log_record("HANDSHAKE SEND FAILED peer:%s port:%d id:%X\n",
        ip,port,id);
    return 1;
  }   


  // Make a peer

  log_record("Attempting connection with peer %s on port %d\n",
      ip,
      port);


  init_peer(peer, id, ip, port);
  *newfd = client_fd;
  log_record("HANDSHAKE SUCCESS peer:%s port:%d id:%X\n",
      inet_ntoa(peer->sockaddr.sin_addr),peer->port,id);
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

  /*
     int i;
     for(i=0;i<12;++i){
     fprintf(stderr,"%c",ip[i]);
     }*/

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


/*
   int load_piece_from_file(FILE * fp, bt_piece_t * piece){
   return 0;
   }
   */
