#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h> //ip hdeader library (must come before ip_icmp.h)
#include <netinet/ip_icmp.h> //icmp header
#include <arpa/inet.h> //internet address library
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>


#include "bencode.h"
#include "bt_lib.h"
#include "bt_setup.h"

#define BUF_LEN 1024

#include <openssl/sha.h> //hashing pieces

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



int main (int argc, char * argv[]){
  bt_args_t bt_args;
  be_node * node; // top node in the bencoding
  int i, maxfd,result, read_size;
  struct timeval tv;
  char h_message[H_MSG_LEN];
  char rh_message[H_MSG_LEN];
  char buf[BUF_LEN];
  int npeers=0;

  log_info log;
  float ms;
  int len;
  // we will always read from read_set and write to write_set;
  fd_set readset, tempset;
  gettimeofday(&(log.start_tv),NULL);

  // Parse and print args
  parse_args(&bt_args, argc, argv);
  if(bt_args.verbose) print_args(&bt_args);

  log.log_file = fopen(bt_args.log_file,"w");



  // Initialize a port to listen for incoming connections
  int incoming_sockfd;
  incoming_sockfd = init_incoming_socket(bt_args.port); 
  // initialize readset
  FD_ZERO(&readset);
  FD_SET(incoming_sockfd, &readset);
  maxfd = incoming_sockfd;




  //read and parse the torrent file
  node = load_be_node(bt_args.torrent_file);
  if(bt_args.verbose) be_dump(node);
  bt_info_t tracker_info;
  node = load_be_node(bt_args.torrent_file);
  parse_bt_info(&tracker_info,node); 


  //TODO fix sha1
  char * sha1;
  sha1 = tracker_info.name;

  // TODO Create bitfield

  bt_bitfield_t bfield;
  bfield.size = (tracker_info.num_pieces)/8 + 1;
  bfield.bitfield = malloc(
      (tracker_info.num_pieces)/8 + 1
      );

  bzero(&bfield.bitfield,(tracker_info.num_pieces)/8 + 1);
  printf("Bitfield created with length: %d\n",
      tracker_info.num_pieces/8 + 1);

  peer_t * peer;
  for(i=0;i<MAX_CONNECTIONS;i++){  
    if(bt_args.peers[i] != NULL){
      npeers++;
      peer = bt_args.peers[i];
      gettimeofday(&(log.cur_tv),NULL);
      ms = (log.cur_tv.tv_sec - log.start_tv.tv_sec)*1000;
      ms += (log.cur_tv.tv_usec - log.start_tv.tv_usec)/1000;
      len = snprintf(log.logmsg,100,"%f HANDSHAKE INIT peer:%s port:%d id:\n",
          ms,inet_ntoa(peer->sockaddr.sin_addr),peer->port);
      int logwr = fwrite(log.logmsg,len,1,log.log_file);

      int * sfd = &(bt_args.sockets[i]);


      if(connect_to_peer(peer, sha1, h_message, rh_message, sfd)){
        gettimeofday(&(log.cur_tv),NULL);
        ms = (log.cur_tv.tv_sec - log.start_tv.tv_sec)*1000;
        ms += (log.cur_tv.tv_usec - log.start_tv.tv_usec)/1000;
        len = snprintf(log.logmsg,100,"%f HANDSHAKE FAILED peer:%s port:%d id:\n",
            ms,inet_ntoa(peer->sockaddr.sin_addr),peer->port);
        logwr = fwrite(log.logmsg,len,1,log.log_file);


        //log contents of handshake, eventually unnecessary
        int j;
        for(j=0;j<68;++j){
          len = snprintf(log.logmsg,100,"%d ",h_message[j]);
          logwr = fwrite(log.logmsg,len,1,log.log_file);
        }
        fwrite("\n",1,1,log.log_file);
        for(j=0;j<68;++j){
          len = snprintf(log.logmsg,100,"%d ",rh_message[j]);
          logwr = fwrite(log.logmsg,len,1,log.log_file);
        }
        fwrite("\n",1,1,log.log_file);



        free(bt_args.peers[i]);
      }else{
        gettimeofday(&(log.cur_tv),NULL);
        ms = (log.cur_tv.tv_sec - log.start_tv.tv_sec)*1000;
        ms += (log.cur_tv.tv_usec - log.start_tv.tv_usec)/1000;
        len = snprintf(log.logmsg,100,"%f HANDSHAKE SUCCESS peer:%s port:%d id:\n",
            ms,inet_ntoa(peer->sockaddr.sin_addr),peer->port);
        logwr = fwrite(log.logmsg,len,1,log.log_file);
        FD_SET(bt_args.sockets[i], &readset); // add to master set
        if (bt_args.sockets[i] > maxfd) { // keep track of the max
          maxfd = bt_args.sockets[i];
        }
      }
    }else{//no more peers left
      break;
    }
  }

  fflush(log.log_file);

  //main client loop
  printf("Starting Main Loop, maxfd:%d\n",maxfd);
  while(1){
    memcpy(&tempset, &readset, sizeof(tempset));
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    result = select(maxfd + 1, &tempset, NULL, NULL, &tv);

    if (result == 0) {
      printf("30 seconds of inactivity\n");
    }
    else if (result < 0 && errno != EINTR) {
      printf("Error in select(): %s\n", strerror(errno));
    }
    else if (result > 0) {
      for(i = 0; i <= maxfd; i++) {
        // if there is a new connection
        if (FD_ISSET(i, &tempset)) {
          if(i == incoming_sockfd){
            int new_client_sockfd;
            int peerpos=-1,j;
            //find first available peer slot
            for(j=0;j<MAX_CONNECTIONS;j++){
              if(bt_args.peers[j] != NULL){
                peerpos=j;
                break;
              }
            }
            if(peerpos==-1){
              printf("Unable to accept new connection - already at max\n");
            }else{
              if(accept_new_peer(incoming_sockfd, sha1,h_message, rh_message,
                    &new_client_sockfd, &log,bt_args.peers[peerpos])){
              }else{
                FD_SET(new_client_sockfd, &readset); // add to master set
                if (new_client_sockfd > maxfd) { // keep track of the max
                  maxfd = new_client_sockfd;
                }
                // TODO send bitfield
                bt_msg_t bitfield_msg;
                bitfield_msg.length = 1+bfield.size;
                bitfield_msg.bt_type = BT_BITFILED;
                bitfield_msg.payload.bitfiled = bfield;
                int sent = send(new_client_sockfd,&bitfield_msg,bitfield_msg.length,0);
                printf("Bitfield sent!  Msg len: %3d, Sent Size %3d\n",bitfield_msg.length,sent);
              }
              fflush(log.log_file);
            }
          }
          else { 
            // otherwise someone else is sending us something
            int message_len;
            read(i,&message_len,sizeof(int));
            unsigned char bt_type;
            read(i,&bt_type,sizeof(bt_type));
            // switch on type of bt_message and handle accordingly
            // TODO change the rest of these to #define vals
            switch(bt_type){
              case BT_CHOKE: //choke
                break;
              case BT_UNCHOKE: //unchoke
                break;
              case BT_INTERSTED: //interested
                break;
              case BT_NOT_INTERESTED: //not interested
                break;
              case BT_HAVE: //have
                break;
              case BT_BITFILED: //bitfield
                printf("bitfield received\n");
                do{
                  read_size = read(i,&buf,BUF_LEN);
                  printf("buf contains: %s\n",buf);
                }while(read_size == BUF_LEN);

                send_bitfield(i,bfield);

                // reply with bitfield
                break;
              case BT_REQUEST: //request
                break; 
              case BT_PIECE: //piece
                break;
              case BT_CANCEL: //cancel
                break;
            }
          }
        }
      }
    }
  }

  //   write pieces to files
  //   udpdate peers choke or unchoke status
  //   responses to have/havenots/interested etc.

  //for peers that are not choked
  //   request pieaces from outcoming traffic

  //check livelenss of peers and replace dead (or useless) peers
  //with new potentially useful peers

  //update peers, 


  return 0;
}
