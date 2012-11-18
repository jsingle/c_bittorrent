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
#include <signal.h>


#include "bencode.h"
#include "bt_lib.h"
#include "bt_setup.h"

int main (int argc, char * argv[]){

  bt_args_t bt_args;
  be_node * node; // top node in the bencoding
  int i;

  parse_args(&bt_args, argc, argv);


  if(bt_args.verbose){
    printf("Args:\n");
    printf("verbose: %d\n",bt_args.verbose);
    printf("save_file: %s\n",bt_args.save_file);
    printf("log_file: %s\n",bt_args.log_file);
    printf("torrent_file: %s\n", bt_args.torrent_file);

    for(i=0;i<MAX_CONNECTIONS;i++){
      if(bt_args.peers[i] != NULL)
        print_peer(bt_args.peers[i]);
    }
    
  }

  //read and parse the torrent file
  node = load_be_node(bt_args.torrent_file);

  if(bt_args.verbose){
    be_dump(node);
  }

  bt_info_t tracker_info;

  node = load_be_node(bt_args.torrent_file);
  parse_bt_info(&tracker_info,node); 
  printf("tracker announce:\t%s",tracker_info.announce);
  
  int j; 

   
  //for(j=0;j < bt_args.n_peers; j++){
  //  printf("Attempting connection with peer %s on port %d\n");

  //}

  peer_t * peer;
  // TODO move into init_peer function
  for(i=0;i<MAX_CONNECTIONS;i++){  
    if(bt_args.peers[i] != NULL)  
      // TODO flesh out add_peer
      add_peer(peer,&bt_args, hostname,port);

      int sock_fd;              // socket file descriptor
      sock_fd = socket(AF_INET, SOCK_STREAM, 0); // 0 is sock stream over IP
    
      printf("Attempting connection with peer %s on port %d\n",
           inet_ntoa(peer->sockaddr.sin_addr),
           peer->port);
      // Connect to socket A Priori
      if(connect(
	  sock_fd, 
	  (const struct sockaddr*) &(peer -> sockaddr), 
	  sizeof(peer -> sockaddr))
          < 0 ){
      perror("Connection failed");
      exit(1);
    }
    bt_args.sockets[i] = sock_fd;
    // TODO add sock_fd to bt_args
    // send handshake
    //print_peer(bt_args.peers[i]);  
  }

  //main client loop
  printf("Starting Main Loop\n");
  while(1){

    //try to accept incoming connection from new peer
       
    
    //poll current peers for incoming traffic
    //   write pieces to files
    //   udpdate peers choke or unchoke status
    //   responses to have/havenots/interested etc.
    
    //for peers that are not choked
    //   request pieaces from outcoming traffic

    //check livelenss of peers and replace dead (or useless) peers
    //with new potentially useful peers
    
    //update peers, 

  }

  return 0;
}
