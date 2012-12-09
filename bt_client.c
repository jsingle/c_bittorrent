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
// sorry bro
bt_args_t bt_args;

//prints final ping stats before exiting
void int_handler(int signum){
  int i;
  for(i=0;i<MAX_CONNECTIONS;i++)  
    close(bt_args.sockets[i]);

  printf("GOODBYE\n");

  exit(1);
}

int main (int argc, char * argv[]){
  be_node * node; // top node in the bencoding
  int i, maxfd,result, read_size;
  struct timeval tv;
  char h_message[H_MSG_LEN];
  char rh_message[H_MSG_LEN];

  //used for logging in main loop
  char msg[25];
  char msginfo[50];

  log_info log;
  // we will always read from read_set and write to write_set;
  fd_set readset, tempset;
  gettimeofday(&(log.start_tv),NULL);

  signal(SIGINT, int_handler);
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

  char * sha1 = malloc(20);//used for handshake
//TODO: fix sha1
  bzero(sha1,20);


  //read and parse the torrent file
  node = load_be_node(bt_args.torrent_file);
  if(bt_args.verbose) be_dump(node);
  bt_info_t tracker_info;
  parse_bt_info(&tracker_info,node); 


  //setup bitfield, piece tracking
  piece_tracker piece_track;
  piece_track.size = tracker_info.num_pieces/8 +1;
  piece_track.msg = (char *)malloc(piece_track.size + 
      sizeof(int)+ 1 + sizeof(size_t) + 3);

  piece_track.last_piece = tracker_info.num_pieces-1;
  piece_track.lp_size = tracker_info.length - 
    (tracker_info.num_pieces-1)*tracker_info.piece_length;

  //bt_msg length + bt_msg bt_type + bitfield size
  piece_track.bitfield = piece_track.msg+sizeof(int)+1 +sizeof(size_t)+3;
  bzero(piece_track.msg,piece_track.size + sizeof(size_t) + 1 +3 +sizeof(int));
  printf("Bitfield created with length: %d\n",(int)piece_track.size);
  if(tracker_info.piece_length>32768){ //2^15
    piece_track.recv_size = 32768;
  }else{
    piece_track.recv_size = tracker_info.piece_length;
  }
  piece_track.recvd_pos = (unsigned long int *)
    malloc(sizeof(unsigned long int)*tracker_info.num_pieces);

  bzero(piece_track.recvd_pos,
      sizeof(unsigned long int)*tracker_info.num_pieces);

  log.len = snprintf(log.logmsg,100,"Setup Piece Tracking, bitfield len %d\n",
      (int)piece_track.size);
  log_write(&log);
  
  
  //deal with savefile
  FILE * savefile = process_savefile(&bt_args,&tracker_info,&piece_track);
  
  
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
    //TODO: still getting connection refused on restart
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
            if(read_msglen == -1){
              perror("Read msg failed");
              continue;
            }
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
              printf("READ FAILED\n");
              //exit(1);
            }
            // switch on type of bt_message and handle accordingly
            int have;
            unsigned char bhave;
            int charpos;
            int proc_b;
            size_t bfsize;
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
                read(i,&bfsize,3);
                read(i,&have,message_len-1);
                bhave = 0x80;
                charpos = have%8;
                bhave=bhave>>charpos;
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
                //read 3 padding bytes from bt_msg_t struct
                read_size = read(i,&bfsize,3);
                //read bitfield size
                read_size = read(i,&bfsize,sizeof(size_t));
                //TODO: unexpected size
                if(bfsize != (size_t)piece_track.size)
                  printf("warning: unexpected bitfield size!!! %d %d\n",
                      (int)bfsize,(int)piece_track.size);

                //read bitfield
                read_size = read(i,peer -> btfield,piece_track.size);
                printf("bitfield received length %d char %c\n",
                    read_size,peer->btfield[0]);

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

                bt_request_t piece_req;
                //TODO:handle request struct
                read_size = read(i,&bfsize,3);//read padding
                read_size = read(i,&piece_req,sizeof(bt_request_t));
                printf("request received\n");
                printf("request index: %d\n",piece_req.index); 
                bhave = 1;
                charpos = (piece_req.index)%8;
                // rev direction
                charpos = 7-charpos;
                bhave<<=charpos;


                // check if we have it
                if ( (piece_track.bitfield[piece_req.index/8]) & bhave ){
                  //if we have it

                  // message
                  bt_msg_t * req_piece_msg = (bt_msg_t *) 
                    malloc(/*bt msg */ sizeof(int) + 
                        sizeof(unsigned char) + 3 + 
                        /* bt_piece_t */ + 2*sizeof(int) + 
                        /*data */ SUBPIECE_LEN );
                  req_piece_msg -> length = sizeof(unsigned char) +3+
                    /* bt_piece_t */ + 2*sizeof(int) + 
                    /*data */ piece_req.length;

                  req_piece_msg -> bt_type = BT_PIECE; 

                  // piece
                  bt_piece_t * requested = &(req_piece_msg -> payload.piece);
                  requested -> index = piece_req.index;
                  requested -> begin = piece_req.begin;

                  /*
                     if(tracker_info.length < (piece_req.index)*
                     tracker_info.piece_length+piece_req.begin + piece_req){
                     }*/


                  // load the appro piece
                  //read_size = load_piece_from_file(save_file,&requested);
                  fseek(savefile,(piece_req.index)*tracker_info.piece_length+piece_req.begin, SEEK_SET);
                  // read into bt_piece_t
                  fread(&(requested -> piece),1,piece_req.length,savefile);
                  // send the message to the peer
                  int sent = send(i,req_piece_msg,
                      sizeof(int) + req_piece_msg->length,0);

                  if(sent == -1){
                    perror("send piece error");
                  }
                  printf("Piece sent!  Msg len: %3d, Sent Size %3d\n",
                      req_piece_msg->length,sent);
                  strcpy(msg,"MESSAGE PIECE TO");
                  snprintf(msginfo,50,"index:%d begin:%d",requested->index,
                      requested->begin);
                  log.len = snprintf(log.logmsg,100,"%s id:%s %s\n",
                      msg,bt_args.peers[peerpos]->id,msginfo);
                  log_write(&log);
                }else{
                  // if we don't have it
                  strcpy(msg,"DON'T HAVE PIECE");
                  strcpy(msginfo,"");
                  log.len = snprintf(log.logmsg,100,"%s id:%s %s\n",
                      msg,bt_args.peers[peerpos]->id,msginfo);
                  log_write(&log);


                }

                //send section
                break; 
              case BT_PIECE: //piece
                printf("bt_piece received\n");
                read_size = read(i,&bfsize,3);
                bt_piece_t recv_piece;
                int data_len = message_len-sizeof(bt_type)-3-sizeof(int)*2;
                int have_read = 0;
                char * recv_data = (char *)malloc(data_len);
                read_size = read(i,&recv_piece,sizeof(int)*2);
                while(have_read<data_len){
                  read_size = read(i,recv_data+have_read,data_len-have_read);
                  have_read+=read_size;
                }
                if(have_read != data_len){
                  printf("piece read error!! size %d doesnt match expected %d\n",
                      read_size,data_len);
                }

                strcpy(msg,"MESSAGE PIECE FROM");
                // parse out piece number


                if(piece_track.recvd_pos[recv_piece.index] == recv_piece.begin){
                  //good to go, offset matches what we currently have

                  if(recv_piece.begin + data_len > tracker_info.piece_length){
                    printf("data received exceeds remaining piece size!\n");
                    data_len = tracker_info.piece_length - recv_piece.begin;
                  }
                  if(recv_piece.index*tracker_info.piece_length+
                      recv_piece.begin
                      > tracker_info.length){
                    printf("data received exceeds end of file!!\n");
                    printf("index*len + begin: %d\n",
                        recv_piece.index*tracker_info.piece_length+
                        recv_piece.begin);
                    printf("index %d, len %d, begin %d, totlen %d\n",
                        recv_piece.index,
                        tracker_info.piece_length,
                        recv_piece.begin,
                        tracker_info.length);
                  }
                  fseek(savefile,recv_piece.index*tracker_info.piece_length + 
                      recv_piece.begin,SEEK_SET);
                  read_size=fwrite(recv_data,1,data_len,savefile);
                  snprintf(msginfo,50,"wrote:%d",read_size);
                  piece_track.recvd_pos[recv_piece.index] += read_size;
                  if(piece_track.recvd_pos[recv_piece.index] > 
                      tracker_info.piece_length){
                    printf("something went wrong, wrote past piece size\n");
                  }

                }
                else if(piece_track.recvd_pos[recv_piece.index] <
                    recv_piece.begin + data_len
                    && piece_track.recvd_pos[recv_piece.index]>recv_piece.begin)
                {
                  //we can read some data

                  data_len -= (piece_track.recvd_pos[recv_piece.index]-
                      recv_piece.begin);

                  if(piece_track.recvd_pos[recv_piece.index] + 
                      data_len > tracker_info.piece_length){
                    printf("data received exceeds remaining piece size!\n");
                    data_len = tracker_info.piece_length - 
                      piece_track.recvd_pos[recv_piece.index];
                  }

                  if(recv_piece.index*(tracker_info.piece_length)
                      +recv_piece.begin
                      > tracker_info.length){
                    printf("data received exceeds end of file!!\n");
                  }

                  fseek(savefile,recv_piece.index*tracker_info.piece_length + 
                      piece_track.recvd_pos[recv_piece.index],SEEK_SET);

                  read_size=fwrite(recv_data + 
                      (piece_track.recvd_pos[recv_piece.index]-recv_piece.begin)
                      ,1,data_len,savefile);
                  snprintf(msginfo,50,"wrote:%d",read_size);
                  piece_track.recvd_pos[recv_piece.index] += read_size;
                  if(piece_track.recvd_pos[recv_piece.index] > 
                      tracker_info.piece_length){
                    printf("something went wrong, wrote past piece size\n");
                  }

                }else{
                  //unusable data
                  printf("received unusable (redundant) data\n");
                  snprintf(msginfo,50,"redundant");
                } 
                log.len = snprintf(log.logmsg,100,"%s id:%s %s new_rpos:%ld\n",
                    msg,bt_args.peers[peerpos]->id,msginfo,
                    piece_track.recvd_pos[recv_piece.index]);
                log_write(&log);


                if(piece_track.recvd_pos[recv_piece.index]==
                    tracker_info.piece_length){
                  //fills block, so sha1 & verify
                  char * piecesha = malloc(20);
                  char * vpiece = malloc(tracker_info.piece_length);
                  fseek(savefile,recv_piece.index*tracker_info.piece_length,
                      SEEK_SET);
                  read_size=fread(vpiece,1,tracker_info.piece_length,
                      savefile);
                  SHA1((unsigned char *)vpiece,tracker_info.piece_length,
                      (unsigned char *)piecesha);
                  if(!memcmp(tracker_info.piece_hashes[recv_piece.index],
                        piecesha,20)){
                    printf("Verified downloaded piece %d\n",recv_piece.index);
                    log.len = snprintf(log.logmsg,100,"VERIFIED PIECE %d\n",
                        recv_piece.index);
                    log_write(&log);

                    unsigned char bitand = 0x80;
                    bitand = bitand>>(recv_piece.index%8);
                    piece_track.bitfield[recv_piece.index/8] |= bitand;
                    test_progress(&piece_track,&tracker_info);
                    send_have(i,recv_piece.index);
                    log.len = snprintf(log.logmsg,100,"MESSAGE HAVE TO peer:%s have:%d\n",
                        peer->id,
                        recv_piece.index);
                    log_write(&log);
                    
                  }else{
                    printf("Verify of piece %d failed!\n",recv_piece.index);
                    piece_track.recvd_pos[recv_piece.index] = 0;
                  }
                }

                //last piece scenario
                if(recv_piece.index == piece_track.last_piece){
                  if(piece_track.recvd_pos[recv_piece.index] == 
                      piece_track.lp_size){
                    char * piecesha = malloc(20);
                    char * vpiece = malloc(piece_track.lp_size);
                    fseek(savefile,recv_piece.index*tracker_info.piece_length,
                        SEEK_SET);
                    read_size=fread(vpiece,1,piece_track.lp_size,
                        savefile);
                    SHA1((unsigned char *)vpiece,piece_track.lp_size,
                        (unsigned char *)piecesha);
                    if(!memcmp(tracker_info.piece_hashes[recv_piece.index],
                          piecesha,20)){
                      printf("Verified downloaded piece %d\n",recv_piece.index);
                      log.len = snprintf(log.logmsg,100,"VERIFIED PIECE %d\n",
                          recv_piece.index);
                      log_write(&log);

                      char bitand = 1<<7;
                      bitand = bitand>>(recv_piece.index%8);
                      piece_track.bitfield[recv_piece.index/8] |= bitand;
                      test_progress(&piece_track,&tracker_info);
                      send_have(i,recv_piece.index);
                    }else{
                      printf("Verify of piece %d failed!\n",recv_piece.index);
                      piece_track.recvd_pos[recv_piece.index] = 0;
                    }
                  }
                }

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
              default:
                printf("unexpected btmsg value received\n");
                exit(1);
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
