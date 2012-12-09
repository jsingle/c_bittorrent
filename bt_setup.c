#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


#include "bt_setup.h"
#include "bt_lib.h"
#include "bencode.h"
#include <arpa/inet.h>

#include <openssl/sha.h>









FILE * process_savefile(bt_args_t * bt_args,
    bt_info_t * tracker_info,
    piece_tracker * piece_track)
{

  int i;
  //deal with savefile
  char * t_file_name;
  if(!strcmp(bt_args->save_file,"")){
    t_file_name = tracker_info->name;
  }else{
    t_file_name = bt_args->save_file;
  }
  FILE * savefile;
  int newf = 0;
  savefile = fopen(t_file_name,"r+");
  if (savefile == NULL){
    printf("Creating new file \"%s\" as savefile\n",t_file_name);
    newf = 1;
    savefile = fopen(t_file_name,"w+");
    if(savefile == NULL){
      perror("Opening savefile failed");
      exit(1);
    }
    fseek(savefile,0L,SEEK_END);
    int file_l = ftell(savefile);
    fseek(savefile,0L,SEEK_SET);
      //make file bigger
      fseek(savefile,tracker_info->length-1,SEEK_SET);
      fwrite("x",1,1,savefile);//writes to ensure proper length
      file_l = ftell(savefile);
      printf("file size set: %d\n",file_l);
  }else{
    printf("Reading and checking existing savefile \"%s\"\n",t_file_name);
    fseek(savefile,0L,SEEK_END);
    int file_l = ftell(savefile);
    printf("file size: %d\n",file_l);
    fseek(savefile,0L,SEEK_SET);
    if(file_l < tracker_info->length){
      //make file bigger
      fseek(savefile,tracker_info->length-1,SEEK_SET);
      fwrite("x",1,1,savefile);//writes to ensure proper length
      file_l = ftell(savefile);
      printf("file size set: %d\n",file_l);
    }else{//only try to verify files that are long enough
    //TODO: deal with savefiles that are too long
    char * piece;
    char * shapiece;
    piece = (char *)malloc(tracker_info->piece_length);
    shapiece = (char *)malloc(20);
    int sread;
    fseek(savefile,0L,SEEK_SET);
    for(i=0;i<tracker_info->num_pieces-1;i++){
      sread = fread(piece,1,tracker_info->piece_length,savefile);
      if(sread != tracker_info->piece_length){
        printf("problem reading savefile: read:%d, wanted:%d fileloc:%ld\n",
            sread, tracker_info->piece_length,ftell(savefile));
      }
      //sha1 of piece into shapiece
      SHA1((unsigned char *)piece,tracker_info->piece_length,
          (unsigned char *)shapiece);
      if(!memcmp(tracker_info->piece_hashes[i],shapiece,20)){
        //printf("Piece %d verified\n",i);
        char bitand = 1;
        bitand = bitand<<7;
        bitand = bitand>>(i%8);
        piece_track->bitfield[i/8] |= bitand;
      }else{
        //printf("Piece %d not verified\n",i);
      }
    }
    //verify last piece
    int last_pl = tracker_info->length
      - tracker_info->piece_length*(tracker_info->num_pieces-1);
    sread = fread(piece,1,last_pl,savefile);
    if(sread != last_pl){
      printf("problem reading savefile: read:%d, wanted:%d fileloc:%ld\n",
          sread, last_pl,ftell(savefile));
    }
    //sha1 of piece into shapiece
    SHA1((unsigned char *)piece,last_pl,
        (unsigned char *)shapiece);
    if(!memcmp(tracker_info->piece_hashes[i],shapiece,20)){
      //printf("Piece %d verified\n",i);
      char bitand = 1;
      bitand = bitand<<7;
      bitand = bitand>>(i%8);
      piece_track->bitfield[i/8] |= bitand;
    }else{
      //printf("Piece %d not verified\n",i);
    }
    //setup bitfield
  }
  int havepieces=0;
  for(i=0;i<tracker_info->num_pieces;i++){
    char bitand = 1<<7;
    if(piece_track->bitfield[i/8] & bitand>>(i%8)){
      if(!havepieces) printf("Have pieces: %d",i);
      else printf(", %d",i);
      havepieces++;
    }
  }
  if(havepieces)printf("\n");
  printf("Have %d of %d pieces, download %d%% completed\n",
      havepieces,tracker_info->num_pieces,(int)(100*havepieces)/tracker_info->num_pieces);
  }

  return savefile;
}


/**
 * usage(FILE * file) -> void
 *
 * print the usage of this program to the file stream file
 *
 **/
void usage(FILE * file){
  if(file == NULL){
    file = stdout;
  }

  fprintf(file,
      "bt-client [OPTIONS] file.torrent\n"
      "  -h            \t Print this help screen\n"
      "  -b port         \t Bind to this port\n"
      "  -s save_file  \t Save the torrent in directory save_dir (dflt: .)\n"
      "  -l log_file   \t Save logs to log_filw (dflt: bt-client.log)\n"
      "  -p ip:port    \t Instead of contacing the tracker for a peer list,\n"
      "                \t use this peer instead, ip:port (ip or hostname)\n"
      "                \t (include multiple -p for more than 1 peer)\n"
      "  -I id         \t Set the node identifier to id (dflt: random)\n"
      "  -v            \t verbose, print additional verbose info\n");
}

/**
 * __parse_peer(peer_t * peer, char peer_st) -> void
 *
 * parse a peer string, peer_st and store the parsed result in peer
 *
 * ERRORS: Will exit on various errors
 **/
void __parse_peer(peer_t * peer, char * peer_st){
  char * parse_str;
  char * word;
  unsigned short port;
  char * ip;
  char id[ID_SIZE];
  char sep[] = ":";
  int i;

  printf("IN PARSE_PEER\n");
  //need to copy becaus strtok mangels things
  parse_str = malloc(strlen(peer_st)+1);
  strncpy(parse_str, peer_st, strlen(peer_st)+1);

  ///only can have 2 tokens max, but may have less
  for(word = strtok(parse_str, sep), i=0; 
      (word && i < 3); 
      word = strtok(NULL,sep), i++){

    printf("%d:%s\n",i,word);
    switch(i){
    case 0://id
      ip = word;
      break;
    case 1://ip
      port = atoi(word);
    default:
      break;
    }

  }

  if(i < 2){
    fprintf(stderr,"ERROR: Parsing Peer: Not enough values in '%s'\n",peer_st);
    usage(stderr);
    exit(1);
  }

  if(word){
    fprintf(stderr, "ERROR: Parsing Peer: Too many values in '%s'\n",peer_st);
    usage(stderr);
    exit(1);
  }


  //calculate the id, value placed in id
  calc_id(ip,port,id);

  //build the object we need
  init_peer(peer, id, ip, port);
  
  //free extra memory
  free(parse_str);

  return;
}

/**
 * pars_args(bt_args_t * bt_args, int argc, char * argv[]) -> void
 *
 * parse the command line arguments to bt_client using getopt and
 * store the result in bt_args.
 *
 * ERRORS: Will exit on various errors
 *
 **/
void parse_args(bt_args_t * bt_args, int argc,  char * argv[]){
  int ch; //ch for each flag
  int n_peers = 0;
  int i;

  /* set the default args */
  bt_args->verbose=0; //no verbosity
  
  //null save_file, log_file and torrent_file
  memset(bt_args->save_file,0x00,FILE_NAME_MAX);
  memset(bt_args->torrent_file,0x00,FILE_NAME_MAX);
  memset(bt_args->log_file,0x00,FILE_NAME_MAX);
  
  //null out file pointers
  bt_args->f_save = NULL;

  //null bt_info pointer, should be set once torrent file is read
  bt_args->bt_info = NULL;

  //default lag file
  strncpy(bt_args->log_file,"bt-client.log",FILE_NAME_MAX);
  
  for(i=0;i<MAX_CONNECTIONS;i++){
    bt_args->peers[i] = NULL; //initially NULL
  }

  bt_args->port = 0;
  bt_args->id = 0;
  
  while ((ch = getopt(argc, argv, "hp:s:l:vI:b:")) != -1) {
    switch (ch) {
    case 'h': //help
      usage(stdout);
      exit(0);
      break;
    case 'v': //verbose
      bt_args->verbose = 1;
      break;
    case 's': //save file
      strncpy(bt_args->save_file,optarg,FILE_NAME_MAX);
      break;
    case 'l': //log file
      strncpy(bt_args->log_file,optarg,FILE_NAME_MAX);
      break;
    case 'b': //port
      bt_args->port = atoi(optarg);
      if(bt_args->port <= 0){
        fprintf(stderr,"ERROR: Invalid port number\n");
        exit(1);
      }
      break;
    case 'p': //peer
      n_peers++;
      //check if we are going to overflow
      if(n_peers > MAX_CONNECTIONS){
        fprintf(stderr,"ERROR: Can only support %d initial peers",MAX_CONNECTIONS);
        usage(stderr);
        exit(1);
      }

      bt_args->peers[n_peers] = malloc(sizeof(peer_t));

      //parse peers
      __parse_peer(bt_args->peers[n_peers], optarg);
      break;
    case 'I':
      bt_args->id = atoi(optarg);
      break;
    default:
      fprintf(stderr,"ERROR: Unknown option '-%c'\n",ch);
      usage(stdout);
      exit(1);
    }
  }


  argc -= optind;
  argv += optind;

  if(argc == 0){
    fprintf(stderr,"ERROR: Require torrent file\n");
    usage(stderr);
    exit(1);
  }

  //copy torrent file over
  strncpy(bt_args->torrent_file,argv[0],FILE_NAME_MAX);

  return ;
}


void print_args(bt_args_t * bt_args){
    int i;
    printf("Args:\n");
    printf("verbose: %d\n",bt_args -> verbose);
    printf("save_file: %s\n",bt_args -> save_file);
    printf("log_file: %s\n",bt_args -> log_file);
    printf("torrent_file: %s\n", bt_args -> torrent_file);

    for(i=0;i<MAX_CONNECTIONS;i++){
      if(bt_args -> peers[i] != NULL)
	print_peer(bt_args -> peers[i]);
    }
}


int parse_bt_info(bt_info_t * out, be_node * node)
{
  size_t i,j;
  be_node * currnode;
  be_node * infonode;
  //bt_info_t out;
  // announce
  // parse dict with info

  for (i = 0; node->val.d[i].val; ++i) {
    currnode = node -> val.d[i].val;
    if(strcmp(node->val.d[i].key,"announce") == 0)
      strcpy(out->announce,currnode->val.s);
    
    else if(strcmp(node->val.d[i].key,"info") == 0){
    for (j = 0; currnode->val.d[j].val; ++j) {
        infonode = currnode -> val.d[j].val;
	
	if(strcmp(currnode->val.d[j].key,"name") == 0)
	  strcpy(out->name,infonode->val.s);
	else if(strcmp(currnode->val.d[j].key,"length") == 0)
	  out->length = infonode->val.i;
	else if(strcmp(currnode->val.d[j].key,"piece length") == 0)        {
	  out->piece_length = infonode->val.i;
	  // once we have the total length and piece length
	  // we can find the number of pieces req'd
	  out -> num_pieces = (out->length)/(out-> piece_length);
	  // handle partial pieces
	  if (out->length%out->piece_length > 0)
	   out -> num_pieces++; 
	}
	
	else if(strcmp(currnode->val.d[j].key,"pieces") == 0)
	{
	  // here we malloc the pieces_hash buffer based
	  // on the number of pieces we have
	  out -> piece_hashes = (char **)malloc(out->num_pieces*sizeof(char *));
          int k;
          for(k=0;k<out->num_pieces;k++){//malloc a sha1 per piece
            out->piece_hashes[k] = (char *)malloc(20);
            memcpy(out->piece_hashes[k],infonode->val.s + 20*k,20);
          }
        }
      }
    }
  }
  return 1;
}



int read_handshake(int peer_sock_fd,char * rh_message,char * h_message){
  int read_size = read(peer_sock_fd,rh_message,68);
  if(read_size == -1){
    perror("Read Handshake Failed");
    return 1;
  }
  
  
  if(read_size != 68){
    printf("Incorrect handshake size received: %d\n",read_size);
    //continue;
    return 1;
  }

  //TODO: compare full handshake, need our IP
  if(memcmp(h_message,rh_message,48)){ //don't match
    printf("Handshake attempted, no match, closing connection: %s\n",rh_message);
    int x;
    printf("hmessage:\n");
    for(x=0;x<68;++x){
      printf("%d ",h_message[x]);
    }
    printf("\nrhmessage:\n");
    for(x=0;x<68;++x){
      printf("%d ",rh_message[x]);
    }
    printf("\n");
    close(peer_sock_fd);
    return 1;
  }else {  //handshake match
    printf("Handshake successful\n");
    return 0;
  }
  return 1;
}


//initializes connection, using handshake, with given peer
int connect_to_peer(peer_t * peer, char * sha1, char * h_message, 
    char * rh_message, int * sfd){

      printf("Attempting connection with peer %s on port %d\n",
          inet_ntoa(peer->sockaddr.sin_addr),
          peer->port);

      // Create socket to handle peer
      int peer_sock_fd;
      peer_sock_fd = socket(AF_INET, SOCK_STREAM, 0); 
      get_peer_handshake(peer,sha1,h_message);

      // Connect to socket A Priori
      if(connect(
            peer_sock_fd, 
            (const struct sockaddr*) &(peer -> sockaddr), 
            sizeof(peer -> sockaddr))
          < 0 ){
        perror("Connection failed");
        return 1;
      }


      int sent = send(peer_sock_fd,h_message,68,0);
      if(sent != 68){//should be 68...
        fprintf(stderr,"handshake send error, returned %d\n",sent);
      } 
      printf("Sent handshake\n");
      *sfd = peer_sock_fd;
      return read_handshake(peer_sock_fd,rh_message,h_message);
}


int init_incoming_socket(int port){
  struct addrinfo hints, *res;

  int sockfd;              //socket file descriptor 
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; // use IPv4 or IPv6, whichever
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE; 

  char port_str[5];
  sprintf(port_str, "%d", port);

  // TODO get right port here
  getaddrinfo(NULL,port_str, &hints, &res);

  sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  bind(sockfd, 
      res -> ai_addr, 
      res->ai_addrlen);


  //TODO: default port is not working somehow
  fprintf(stderr,"Server bound to socket on socket_fd %d, on port %s\n",
      sockfd,port_str);

  // initialize socket to listen for incoming
  if(-1 == listen(sockfd,10)){ // 10 is the max number of backlogged requests 
    perror("Error initializing passive socket to accept incoming connections");
  } 

  return sockfd;
}
