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
  // we will always read from read_set and write to write_set;
  fd_set readset, tempset;

  // PRINT ARGS
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

  peer_t * peer;
  // TODO move into init_peer function
  for(i=0;i<MAX_CONNECTIONS;i++){  
    if(bt_args.peers[i] != NULL){  
      peer = bt_args.peers[i];
      bt_args.sockets[i] = connect_to_peer(peer, sha1, h_message, rh_message);
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

      if (FD_ISSET(incoming_sockfd, &tempset)) {
	int new_client_sockfd;
        new_client_sockfd = accept_new_peer(incoming_sockfd, sha1,h_message, rh_message);
      }
    }
  }

  //   poll current peers for incoming traffic
  //rc = 



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
