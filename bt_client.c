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

#include <openssl/sha.h> //hashing pieces
int main (int argc, char * argv[]){
  bt_args_t bt_args;
  be_node * node; // top node in the bencoding
  int i, maxfd,flags,result;
  struct timeval tv;
  char h_message[H_MSG_LEN];
  char rh_message[H_MSG_LEN];
  char buf[1024];
  // we will always read from read_set and write to write_set;
  fd_set readset, tempset;

  // Parse and print args
  parse_args(&bt_args, argc, argv);
  if(bt_args.verbose) print_args(&bt_args);

 

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
  bfield.size = (tracker_info.num_pieces)/sizeof(char);
  bfield.bitfield = malloc(
    (tracker_info.num_pieces)/sizeof(char)
  );


  peer_t * peer;
  for(i=0;i<MAX_CONNECTIONS;i++){  
    if(bt_args.peers[i] != NULL){  
      peer = bt_args.peers[i];
      bt_args.sockets[i] = connect_to_peer(peer, sha1, h_message, rh_message);
      FD_SET(bt_args.sockets[i], &readset); // add to master set
    }
  }


  //main client loop
  printf("Starting Main Loop\n");
  while(1){
    memcpy(&tempset, &readset, sizeof(tempset));
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    result = select(maxfd + 1, &tempset, NULL, NULL, &tv);

    if (result == 0) {
      printf("select() timed out!\n");
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
	    new_client_sockfd = accept_new_peer(incoming_sockfd, sha1,h_message, rh_message);
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
	    printf("Bitfield sent!\n");
	  }
	  else { 
	    // otherwise someone else is sending us something
            
	    int message_len;
	    read(i,&message_len,sizeof(int));
	    unsigned char bt_type;
	    read(i,&bt_type,sizeof(bt_type));
	    // switch on type of bt_message and handle accordingly
	    // TODO change the rest of these to #define vals
            switch(i){
            case 0: //choke
	      break;
            case 1: //unchoke
	      break;
	    case 2: //interested
	      break;
	    case 3: //not interested
	      break;
	    case 4: //have
	      break;
	    case BT_BITFILED: //bitfield
	      printf("bitfield received\n");
	      //read(i,&buf,sizeof(message_len));
	      
	      // reply with bitfield
	      break;
	    case 6: //request
	      break; 
	    case 7: //piece
	      break;
	    case 8: //cancel
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
