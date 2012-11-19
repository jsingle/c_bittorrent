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
 
  // PRINT ARGS
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

  // Initialize a port to listen for incoming connections
  struct addrinfo hints, *res;
  int sockfd;              //socket file descriptor 
  
  //handshake message goes in h_message,
  //received handshake in rh_message
  char * h_message, * rh_message;
  if( (h_message=(char*)malloc(68)) == NULL){
    //malloc failed
    fprintf(stderr,"memory error\n");
    exit(1);
  }
  if( (rh_message=(char*)malloc(68)) == NULL){
    //malloc failed
    fprintf(stderr,"memory error\n");
    exit(1);
  }

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; // use IPv4 or IPv6, whichever
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE; 
  
  char port_str[5];

  //itoa(bt_args.port,port_str,10);// get bt_args.port as str
  sprintf(port_str, "%d", bt_args.port);

  // TODO get right port here
  getaddrinfo(NULL,port_str, &hints, &res);
  
  sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  bind(sockfd, 
      res -> ai_addr, 
      res->ai_addrlen);

  fprintf(stderr,"Server bound to socket on socket_fd %d\n",sockfd);

  // initialize socket to listen for incoming
  if(-1 == listen(
	sockfd,
	10) // 10 is the max number of backlogged requests 
    ){
    perror("Error initializing passive socket to accept incoming connections");
  } 

  //read and parse the torrent file
  node = load_be_node(bt_args.torrent_file);

  if(bt_args.verbose){
    be_dump(node);
  }

  bt_info_t tracker_info;

  node = load_be_node(bt_args.torrent_file);
  parse_bt_info(&tracker_info,node); 
  printf("Tracker Announce:\t%s\n",tracker_info.announce);

  peer_t * peer;
  // TODO move into init_peer function
  for(i=0;i<MAX_CONNECTIONS;i++){  
    if(bt_args.peers[i] != NULL){  
      peer = bt_args.peers[i];
      
      printf("Attempting connection with peer %s on port %d\n",
          inet_ntoa(peer->sockaddr.sin_addr),
          peer->port);

      // Create socket to handle peer
      int peer_sock_fd;
      peer_sock_fd = socket(AF_INET, SOCK_STREAM, 0); 

      // Connect to socket A Priori
      if(connect(
            peer_sock_fd, 
            (const struct sockaddr*) &(peer -> sockaddr), 
            sizeof(peer -> sockaddr))
          < 0 ){
        perror("Connection failed");
        exit(1);
      }

      bt_args.sockets[i] = peer_sock_fd;
      // TODO add sock_fd to bt_args

      //TODO fix sha1
      char * sha1;
      sha1 = tracker_info.announce;
      
      get_peer_handshake(peer,sha1,h_message);
      int sent = send(peer_sock_fd,h_message,68,0);
      if(sent != 68){
        //should be 68...
        fprintf(stderr,"handshake send error, returned %d\n",sent);
      } 
      int read_size = read(peer_sock_fd,rh_message,68);
      if(read_size != 68){
        printf("Incorrect handshake size received: %d\n",read_size);
        //continue;
      }
      
      if(memcmp(h_message,rh_message,48)){ //don't match
        printf("Handshake attempted, no match, closing connection: %s\n",
            rh_message);
        close(peer_sock_fd);
      }else {  //handshake match
        printf("Handshake successful\n");
        //TODO: what comes next??
      }

      //print_peer(bt_args.peers[i]);  
    }
  }

  
  //main client loop
  printf("Starting Main Loop\n");
  while(1){
    //try to accept incoming connection from new peer 
    // Wait for a connection on the socket
    int client_fd;              // socket file descriptor
    struct sockaddr client_addr;
    socklen_t client_addr_len; 
    printf("Waiting for connection...\n");
    client_fd = accept(
	sockfd,//int socket, 
	&client_addr,//struct sockaddr * address, 
	&client_addr_len//socklent_t * address_len
	);
      
    //TODO: fix sha
    char * sha1;
    sha1 = tracker_info.announce;
    
    get_peer_handshake(peer,sha1,h_message);
    int read_size = read(client_fd,rh_message,68);
    if(read_size != 68){
      printf("Incorrect handshake size received: %d\n",read_size);
      continue;
    }
    int sent = send(client_fd,h_message,68,0);
    if(sent != 68){
      //should be 68...
      fprintf(stderr,"handshake send error, returned %d\n",sent);
    } 
    if(memcmp(h_message,rh_message,48)){ //don't match
      printf("Handshake attempted, no match, closing connection: %s\n",
          rh_message);
      close(client_fd);
    }else {  //handshake match
      printf("Handshake successful\n");
      //TODO: what comes next??
    }
    fprintf(stderr,"Connection established with client\n");


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
