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


int main (int argc, char * argv[]){
  bt_args_t bt_args;
  be_node * node; // top node in the bencoding
  int i, maxfd,result, read_size;
  struct timeval tv;
  char h_message[H_MSG_LEN];
  char rh_message[H_MSG_LEN];
  char buf[BUF_LEN];

  //used for logging in main loop
  char msg[25];
  char msginfo[50];

  log_info log;
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

  
  
  // TODO parse data file, create bitfield for restart
 

  piece_tracker piece_track;
  piece_track.size = tracker_info.num_pieces/8 +1;
  piece_track.msg = (char *)malloc(piece_track.size + sizeof(int)+ 1);
  piece_track.bitfield = piece_track.msg+sizeof(int)+1;
  bzero(piece_track.msg,piece_track.size + sizeof(size_t) + 1);
  printf("Bitfield created with length: %d\n",(int)piece_track.size);
  if(tracker_info.piece_length>32768){ //2^15
    piece_track.recv_size = 32768;
  }else{
    piece_track.recv_size = tracker_info.piece_length;
  }
  piece_track.recvd_pos = (unsigned long int *)
    malloc(sizeof(unsigned long int)*piece_track.size);




  //TODO: connections should initially be choked and uninterested
  peer_t * peer;
  for(i=0;i<MAX_CONNECTIONS;i++){  
    if(bt_args.peers[i] != NULL){
      //setup peer btfields
      peer = bt_args.peers[i];
      peer->btfield = malloc(piece_track.size);
      bzero(peer->btfield,piece_track.size);
      log.len = snprintf(log.logmsg,100,"HANDSHAKE INIT peer:%s port:%d id:%20s\n",
          inet_ntoa(peer->sockaddr.sin_addr),peer->port,peer->id);
      int logwr = log_write(&log);

      int * sfd = &(bt_args.sockets[i]);


      if(connect_to_peer(peer, sha1, h_message, rh_message, sfd)){
        log.len = snprintf(log.logmsg,100,"HANDSHAKE FAILED peer:%s port:%d id:%20s\n",
            inet_ntoa(peer->sockaddr.sin_addr),peer->port,peer->id);
        logwr = log_write(&log);

        free(bt_args.peers[i]);
      }else{
        log.len = snprintf(log.logmsg,100,"HANDSHAKE SUCCESS peer:%s port:%d id:%20s\n",
            inet_ntoa(peer->sockaddr.sin_addr),peer->port,peer->id);
        logwr = log_write(&log);
        FD_SET(bt_args.sockets[i], &readset); // add to master set
        if (bt_args.sockets[i] > maxfd) { // keep track of the max
          maxfd = bt_args.sockets[i];
        }
        send_bitfield(bt_args.sockets[i],&piece_track,peer,&log);
      }
    }
  }

  //indicates whether "unable to connect, max connections" needs
  //to be printed
  int maxconnect=0;

  //main client loop
  printf("Starting Main Loop, maxfd:%d\n",maxfd);
  while(1){
    //TODO: need to handle clients closing connections
    //also clients need to handle server closing connections
    int peerpos=-1,j;
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
            //there is new client trying to connect
            

            int new_client_sockfd;
            //find first available peer slot
            peerpos=-1;
            for(j=0;j<MAX_CONNECTIONS;j++){
              if(bt_args.peers[j] == NULL){
                peerpos=j;
                maxconnect = 0;
                break;
              }
            }
            if(peerpos==-1){//cant find an empty slot, so we're at max_connect
              if(maxconnect) continue;
              printf("Unable to accept new connection - already at max\n");
              maxconnect = 1;
            }else{
              bt_args.peers[peerpos] = malloc(sizeof(peer_t));
              if(accept_new_peer(incoming_sockfd, sha1,h_message, rh_message,
                    &new_client_sockfd, &log,bt_args.peers[peerpos])){
                free(bt_args.peers[peerpos]);
                bt_args.peers[peerpos] = NULL;
              }else{
                bt_args.peers[peerpos]->btfield = malloc(piece_track.size);
                // accept new peer succeeded
                FD_SET(new_client_sockfd, &readset); // add to master set
                if (new_client_sockfd > maxfd) { // keep track of the max
                  maxfd = new_client_sockfd;
                }
                bt_args.sockets[peerpos] = new_client_sockfd;
                send_bitfield(new_client_sockfd,&piece_track,
                    bt_args.peers[peerpos],
                    &log);
              }
            }
          }
          else { 
            // otherwise someone else is sending us something
            
            
            int message_len;
            int read_msglen = read(i,&message_len,sizeof(int));
            if(!message_len || !read_msglen) continue;
            printf("received %d from file descripter : %d\n",read_msglen,i); 

            // find the peer in the list
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

            peer = bt_args.peers[j];
            unsigned char bt_type;
            int how_much = read(i,&bt_type,sizeof(bt_type));

            printf("READ: %3d \t BT_TYPE : %d \n",how_much,bt_type);
            if (!how_much){
              printf("READ FAILED");
              //exit(1);
            }
            // switch on type of bt_message and handle accordingly
            int have;
            unsigned char bhave;
            int charpos;
            int proc_b;
            switch(bt_type){
              case BT_CHOKE: //choke
                bt_args.peers[peerpos]->imchoked=1;
                strcpy(msg,"MESSAGE CHOKE FROM");
                strcpy(msginfo,"");
                log.len = snprintf(log.logmsg,100,"%s id:%s %s\n",
                    msg,bt_args.peers[peerpos]->id,msginfo);
                log_write(&log);
                break;
              case BT_UNCHOKE: //unchoke
                bt_args.peers[peerpos]->imchoked=0;
                strcpy(msg,"MESSAGE UNCHOKE FROM");
                strcpy(msginfo,"");
                log.len = snprintf(log.logmsg,100,"%s id:%s %s\n",
                    msg,bt_args.peers[peerpos]->id,msginfo);
                log_write(&log);
                break;
              case BT_INTERSTED: //interested
                bt_args.peers[peerpos]->interested=1;
                strcpy(msg,"MESSAGE INTERESTED FROM");
                strcpy(msginfo,"");
                log.len = snprintf(log.logmsg,100,"%s id:%s %s\n",
                    msg,bt_args.peers[peerpos]->id,msginfo);
                log_write(&log);
                break;
              case BT_NOT_INTERESTED: //not interested
                bt_args.peers[peerpos]->interested=0;
                strcpy(msg,"MESSAGE NOT INTERESTED FROM");
                strcpy(msginfo,"");
                log.len = snprintf(log.logmsg,100,"%s id:%s %s\n",
                    msg,bt_args.peers[peerpos]->id,msginfo);
                log_write(&log);
                break;
              case BT_HAVE: //have
                read(i,&have,message_len-1);
                bhave = 1;
                charpos = have%8;
                charpos = 7-charpos;
                bhave<<=charpos;
                bt_args.peers[peerpos]->btfield[have/8] |= bhave;
                strcpy(msg,"MESSAGE HAVE FROM");
                snprintf(msginfo,50,"have:%d",have);
                log.len = snprintf(log.logmsg,100,"%s id:%s %s\n",
                    msg,bt_args.peers[peerpos]->id,msginfo);
                log_write(&log);
                if(is_interested(&piece_track,peer,i,&log))
                  proc_b = process_bitfield(&piece_track,peer,i,&log);
                break;
              case BT_BITFILED: //bitfield
                //printf("want bfield size of: %d for bfield\n",(int)bfield.size);
                read_size = read(i,peer -> btfield,piece_track.size);
                printf("bitfield received\n");

                strcpy(msg,"MESSAGE BITFIELD FROM");
                snprintf(msginfo,piece_track.size + 9,"bitfield:%s",
                    peer->btfield);
                log.len = snprintf(log.logmsg,100,"%s id:%s %s\n",
                    msg,bt_args.peers[peerpos]->id,msginfo);
                log_write(&log);
                if(is_interested(&piece_track,peer,i,&log))
                  proc_b = process_bitfield(&piece_track,peer,i,&log);
                break;
              case BT_REQUEST: //request
                strcpy(msg,"MESSAGE REQUEST FROM");
                strcpy(msginfo,"");
                log.len = snprintf(log.logmsg,100,"%s id:%s %s\n",
                    msg,bt_args.peers[peerpos]->id,msginfo);
                log_write(&log);
                //TODO:handle request struct
                //send section
                break; 
              case BT_PIECE: //piece
                printf("bt_piece received\n");
                read_size = read(i,peer->btfield,message_len - sizeof(bt_type));
                strcpy(msg,"MESSAGE PIECE FROM");
                strcpy(msginfo,"");
                log.len = snprintf(log.logmsg,100,"%s id:%s %s\n",
                    msg,bt_args.peers[peerpos]->id,msginfo);
                log_write(&log);
                //TODO:store piece
                //if fills block, sha1 & verify
                //then have
                if(is_interested(&piece_track,peer,i,&log))
                  proc_b = process_bitfield(&piece_track,peer,i,&log);
                break;
              case BT_CANCEL: //cancel
                strcpy(msg,"MESSAGE CANCEL FROM");
                strcpy(msginfo,"");
                log.len = snprintf(log.logmsg,100,"%s id:%s %s\n",
                    msg,bt_args.peers[peerpos]->id,msginfo);
                log_write(&log);
                //TODO: cancel
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
