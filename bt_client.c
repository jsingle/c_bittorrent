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

bt_args_t bt_args;
log_info logger;

//prints final ping stats before exiting
void int_handler(int signum){
  int i;
  for(i=0;i<MAX_CONNECTIONS;i++){ 
    close(bt_args.sockets[i]);
    free(bt_args.peers[i]->btfield);
    free(bt_args.peers[i]);
  }

  printf("GOODBYE\n");

  fclose(logger.log_file);

  exit(1);
}

int main (int argc, char * argv[]){
  be_node * node; // top node in the bencoding
  int i, maxfd,result, read_size;
  struct timeval tv;
  char h_message[H_MSG_LEN];
  char rh_message[H_MSG_LEN];

  //bt_args_t bt_args;
  //log_info log;

  //used for logging in main loop
  char msg[25];
  char msginfo[50];

  // we will always read from read_set and write to write_set;
  fd_set readset, tempset;
  gettimeofday(&(logger.start_tv),NULL);

  signal(SIGINT, int_handler);
  // Parse and print args
  parse_args(&bt_args, argc, argv);
  if(bt_args.verbose) print_args(&bt_args);

  logger.log_file = fopen(bt_args.log_file,"w");


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
  parse_bt_info(&tracker_info,node); 

  //sha1 hash of name field
  char * sha1 = malloc(20);//used for handshake
  bzero(sha1,20);
  char null_padded_name[20] = {0};
  strncpy(null_padded_name,tracker_info.name,strlen(tracker_info.name) -1 );
  printf("Doing sha1 of %s",tracker_info.name);
  SHA1((unsigned char *) null_padded_name, 20,
      (unsigned char *)sha1);



  //setup bitfield, piece tracking
  piece_tracker piece_track;
  piece_track.size = tracker_info.num_pieces/8 +1;
  piece_track.msg = (char *)malloc(piece_track.size + 
      sizeof(int)+ 1 + sizeof(size_t) + 3);// FREE'D
  piece_track.last_piece = tracker_info.num_pieces-1;
  piece_track.lp_size = tracker_info.length - 
    (tracker_info.num_pieces-1)*tracker_info.piece_length;

  //bt_msg length + bt_msg bt_type + bitfield size
  piece_track.bitfield = piece_track.msg+sizeof(int)+1 +sizeof(size_t)+3;
  bzero(piece_track.msg,piece_track.size + sizeof(size_t) + 1 +3 +sizeof(int));
  // SHOULD THIS HAPPEN HERE?
  free(piece_track.msg);

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

  log_record("Setup Piece Tracking, bitfield len %d\n",
      (int)piece_track.size);


  //deal with savefile
  FILE * savefile = process_savefile(&bt_args,&tracker_info,&piece_track);

  //TODO: peer ids in handshake, we need to get our ip (see piazza)
  //TODO: cleanup printed output
  //TODO: more code comments? in bt_lib.c
  //TODO: readme
  //TODO: free all memory malloced
  //TODO: choking protocol?  optional


  //TODO: connections should initially be choked and uninterested
  //so we need code to initialize, then unchoke them, etc
  //TODO: modularize code
  //
  //

  setup_peer_bitfields(sha1,&piece_track,h_message,rh_message);


  // setup readsets
  for(i=0; i<MAX_CONNECTIONS;i++){
    if (bt_args.peers[i] != NULL){

      FD_SET(bt_args.sockets[i], &readset); // add to master set
      if (bt_args.sockets[i] > maxfd) { // keep track of the max
        maxfd = bt_args.sockets[i];
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
    //TODO: still getting connection refused on restart (maybe? hasn't happened in a while)
    //TODO: log clients closing connections, connecting
    int peerpos=-1,j;
    memcpy(&tempset, &readset, sizeof(tempset));
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    result = select(maxfd + 1, &tempset, NULL, NULL, &tv);

    if (result == 0) {
      log_record("30 seconds of inactivity\n");
    }
    else if (result < 0 && errno != EINTR) {
      log_record("Error in select(): %s\n", strerror(errno));
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
              bt_args.peers[peerpos] = malloc(sizeof(peer_t)); // FREE'D
              if(accept_new_peer(incoming_sockfd, sha1,h_message, rh_message,
                    &new_client_sockfd, &logger,bt_args.peers[peerpos])){
                free(bt_args.peers[peerpos]);
                bt_args.peers[peerpos] = NULL;
              }else{
                bt_args.peers[peerpos]->btfield = malloc(piece_track.size); // FREE'D
                // accept new peer succeeded
                FD_SET(new_client_sockfd, &readset); // add to master set
                if (new_client_sockfd > maxfd) { // keep track of the max
                  maxfd = new_client_sockfd;
                }
                bt_args.sockets[peerpos] = new_client_sockfd;
                send_bitfield(new_client_sockfd,&piece_track,
                    bt_args.peers[peerpos],
                    &logger);
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
            //printf("received %d from file descripter : %d\n",read_msglen,i); 

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

            peer_t * peer;
            peer = bt_args.peers[j];
            unsigned char bt_type;
            int how_much = read(i,&bt_type,sizeof(bt_type));

            //printf("READ: %3d \t BT_TYPE : %d \n",how_much,bt_type);
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

                log_record("MESSAGE CHOKE FROM id:%X\n",
                    msg,bt_args.peers[peerpos]->id);

                break;
              case BT_UNCHOKE: //unchoke
                bt_args.peers[peerpos]->imchoked=0;
                log_record("MESSAGE UNCHOKE FROM id:%X\n",
                    bt_args.peers[peerpos]->id);


                break;
              case BT_INTERSTED: //interested
                bt_args.peers[peerpos]->interested=1;

                log_record("MESSAGE INTERESTED FROM id:%X\n",
                    bt_args.peers[peerpos]->id);


                break;
              case BT_NOT_INTERESTED: //not interested
                bt_args.peers[peerpos]->interested=0;

                log_record("MESSAGE NOT INTERESTED FROM id:%X\n",
                    bt_args.peers[peerpos]->id);

                break;
              case BT_HAVE: //have
                read(i,&bfsize,3);
                read(i,&have,message_len-1);
                bhave = 0x80;
                charpos = have%8;
                bhave=bhave>>charpos;
                bt_args.peers[peerpos]->btfield[have/8] |= bhave;
                log_record("MESSAGE HAVE FROM id:%X %d\n",
                    bt_args.peers[peerpos]->id,have);


                if(is_interested(&piece_track,peer,i,&logger))
                  proc_b = process_bitfield(&piece_track,peer,i,&logger);
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
                printf("bitfield received length %d\n",
                    read_size);


                log_record("MESSAGE BITFIELD FROM id:%X bitfield %s\n",
                    bt_args.peers[peerpos]->id,peer->btfield);


                if(is_interested(&piece_track,peer,i,&logger))
                  proc_b = process_bitfield(&piece_track,peer,i,&logger);
                break;
              case BT_REQUEST: //request

                log_record("MESSAGE REQUEST FROM id:%X\n",
                    bt_args.peers[peerpos]->id);


                bt_request_t piece_req;
                //TODO:handle request struct
                read_size = read(i,&bfsize,3);//read padding
                read_size = read(i,&piece_req,sizeof(bt_request_t));
                //printf("request received\n");
                //printf("request index: %d\n",piece_req.index); 
                bhave = 0x80;
                charpos = (piece_req.index)%8;
                // rev direction
                bhave = bhave>>charpos;


                // check if we have it
                if ( (piece_track.bitfield[piece_req.index/8]) & bhave ){
                  //if we have it

                  // message
                  bt_msg_t * req_piece_msg = (bt_msg_t *) 
                    malloc(/*bt msg */ sizeof(int) + 
                        sizeof(unsigned char) + 3 + 
                        /* bt_piece_t */ + 2*sizeof(int) + 
                        /*data */ SUBPIECE_LEN ); // FREE'D
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
                  //printf("Piece sent!  Msg len: %3d, Sent Size %3d\n",
                  //    req_piece_msg->length,sent);

                  log_record("MESSAGE PIECE TO id:%X index:%d begin:%d",
                      bt_args.peers[peerpos]->id,requested->index,
                      requested->begin);

                  free(req_piece_msg);
                }else{
                  // if we don't have it
                  log_record("DON'T HAVE PIECE id:%X\n",
                      bt_args.peers[peerpos]->id);
                }

                log_record("DON'T HAVE PIECE id:%X\n",
                    bt_args.peers[peerpos]->id);

                //send section
                break; 
              case BT_PIECE: //piece
                //printf("bt_piece received\n");
                read_size = read(i,&bfsize,3);
                bt_piece_t recv_piece;
                int data_len = message_len-sizeof(bt_type)-3-sizeof(int)*2;
                int have_read = 0;
                char * recv_data = (char *)malloc(data_len); //FREE'D
                read_size = read(i,&recv_piece,sizeof(int)*2);
                while(have_read<data_len){
                  read_size = read(i,recv_data+have_read,data_len-have_read);
                  have_read+=read_size;
                }
                if(have_read != data_len){
                  printf("piece read error! size %d doesnt match expected %d\n",
                      read_size,data_len);
                }

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
                  free(recv_data);
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

                log_record("MESSAGE PIECE FROM id:%X %s new_rpos:%ld\n",
                    bt_args.peers[peerpos]->id,msginfo,
                    piece_track.recvd_pos[recv_piece.index]);


                if(piece_track.recvd_pos[recv_piece.index]==
                    tracker_info.piece_length){
                  //fills block, so sha1 & verify
                  char * piecesha = malloc(20); // FREE'D
                  char * vpiece = malloc(tracker_info.piece_length); // FREE'D
                  fseek(savefile,recv_piece.index*tracker_info.piece_length,
                      SEEK_SET);
                  read_size=fread(vpiece,1,tracker_info.piece_length,
                      savefile);
                  SHA1((unsigned char *)vpiece,tracker_info.piece_length,
                      (unsigned char *)piecesha);
                  if(!memcmp(tracker_info.piece_hashes[recv_piece.index],
                        piecesha,20)){
                    printf("Verified downloaded piece %d\n",recv_piece.index);


                    log_record("VERIFIED PIECE %d\n",
                        recv_piece.index);


                    unsigned char bitand = 0x80;
                    bitand = bitand>>(recv_piece.index%8);
                    piece_track.bitfield[recv_piece.index/8] |= bitand;
                    test_progress(&piece_track,&tracker_info);
                    send_have(i,recv_piece.index);

                    log_record("MESSAGE HAVE TO peer:%X have:%d\n",
                        peer->id,
                        recv_piece.index);


                  }else{
                    printf("Verify of piece %d failed!\n",recv_piece.index);
                    piece_track.recvd_pos[recv_piece.index] = 0;
                  }
                  free(piecesha);
                }

                //last piece scenario
                if(recv_piece.index == piece_track.last_piece){
                  if(piece_track.recvd_pos[recv_piece.index] == 
                      piece_track.lp_size){
                    char * piecesha = malloc(20); // FREE'D
                    char * vpiece = malloc(piece_track.lp_size); //FREE'D
                    fseek(savefile,recv_piece.index*tracker_info.piece_length,
                        SEEK_SET);
                    read_size=fread(vpiece,1,piece_track.lp_size,
                        savefile);
                    SHA1((unsigned char *)vpiece,piece_track.lp_size,
                        (unsigned char *)piecesha);
                    free(vpiece);
                    if(!memcmp(tracker_info.piece_hashes[recv_piece.index],
                          piecesha,20)){
                      printf("Verified downloaded piece %d\n",recv_piece.index);

                      log_record("VERIFIED PIECE %d\n",
                          recv_piece.index);

                      char bitand = 1<<7;
                      bitand = bitand>>(recv_piece.index%8);
                      piece_track.bitfield[recv_piece.index/8] |= bitand;
                      test_progress(&piece_track,&tracker_info);
                      send_have(i,recv_piece.index);
                    }else{
                      printf("Verify of piece %d failed!\n",recv_piece.index);
                      piece_track.recvd_pos[recv_piece.index] = 0;
                    }

                    free(piecesha);
                  }
                }

                if(is_interested(&piece_track,peer,i,&logger))
                  proc_b = process_bitfield(&piece_track,peer,i,&logger);
                break;
              case BT_CANCEL: //cancel

                log_record("MESSAGE CANCEL FROM id: %X\n",
                    bt_args.peers[peerpos]->id);


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



  //TODO:  (?)
  //check livelenss of peers and replace dead (or useless) peers
  //with new potentially useful peers
  //update peers, 


  return 0;
}
