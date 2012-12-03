#ifndef _BT_LIB_H
#define _BT_LIB_H

//standard stuff
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <poll.h>

//networking stuff
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#include "bt_lib.h"
#include "bencode.h"


/*Maximum file name size, to make things easy*/
#define FILE_NAME_MAX 1024

/*Maxium number of connections*/
#define MAX_CONNECTIONS 5

/*initial port to try and open a listen socket on*/
#define INIT_PORT 6667 

/*max port to try and open a listen socket on*/
#define MAX_PORT 6699

/*Different BitTorrent Message Types*/
#define BT_CHOKE 0
#define BT_UNCHOKE 1
#define BT_INTERSTED 2
#define BT_NOT_INTERESTED 3
#define BT_HAVE 4
#define BT_BITFILED 5
#define BT_REQUEST 6
#define BT_PIECE 7
#define BT_CANCEL 8

/*size (in bytes) of id field for peers*/
#define ID_SIZE 20

#define H_MSG_LEN 68


typedef struct {
  FILE * log_file;
  struct timeval start_tv, cur_tv;
  char logmsg[100];
} log_info;


//holds information about a peer
typedef struct peer{
  unsigned char id[ID_SIZE]; //the peer id
  unsigned short port; //the port to connect n
  struct sockaddr_in sockaddr; //sockaddr for peer
  int choked; //peer choked?
  int interested; //peer interested?
  int imchoked;
  char * btfield;
}peer_t;


//holds information about a torrent file
typedef struct {
  char announce[FILE_NAME_MAX]; //url of tracker
  char name[FILE_NAME_MAX]; //name of file
  int piece_length; //number of bytes in each piece
  int length; //length of the file in bytes
  int num_pieces; //number of pieces, computed based on above two values

  //pointer to 20 byte data buffers of the sha1sum of each of the pieces:
  char ** piece_hashes; 
} bt_info_t;


//holds all the agurments and state for a running the bt client
typedef struct {
  int verbose; //verbose level
  char save_file[FILE_NAME_MAX];//the filename to save to
  FILE * f_save;
  char log_file[FILE_NAME_MAX];//the log file
  char torrent_file[FILE_NAME_MAX];// *.torrent file
  peer_t * peers[MAX_CONNECTIONS]; // array of peer_t pointers
  unsigned int id; //this bt_clients id
  int sockets[MAX_CONNECTIONS]; //Array of possible sockets

  //Arry of pollfd for polling for input:
  struct pollfd poll_sockets[MAX_CONNECTIONS];   
  /*set once torrent is parse*/
  bt_info_t * bt_info; //the parsed info for this torrent
  int port;
  

} bt_args_t;


/**
 * Message structures
 **/

typedef struct {
  char * bitfield; //bitfield where each bit represents a piece that
                   //the peer has or doesn't have
  size_t size;//size of the bitfiled
} bt_bitfield_t;

typedef struct{
  int index; //which piece index
  int begin; //offset within piece
  int length; //amount wanted, within a power of two
} bt_request_t;

typedef struct{
  int index; //which piece index
  int begin; //offset within piece
  char piece[0]; //pointer to start of the data for a piece
} bt_piece_t;



typedef struct bt_msg{
  int length; //length of remaining message, 
              //0 length message is a keep-alive message
  unsigned char bt_type;//type of bt_mesage

  //payload can be any of these
  union { 
    bt_bitfield_t bitfiled;//send a bitfield
    int have; //what piece you have
    bt_piece_t piece; //a peice message
    bt_request_t request; //request messge
    bt_request_t cancel; //cancel message, same type as request
    char data[0];//pointer to start of payload, just incase
  }payload;

} bt_msg_t;





int parse_bt_info(bt_info_t * bt_info, be_node * node);

/*choose a random id for this node*/
unsigned int select_id();

/*propogate a peer_t struct and add it to the bt_args structure*/
int add_peer(peer_t *peer, bt_args_t *bt_args, char * hostname, unsigned short port);

/*drop an unresponsive or failed peer from the bt_args*/
int drop_peer(peer_t *peer, bt_args_t *bt_args);

/* initialize connection with peers */
int init_peer(peer_t *peer, char * id, char * ip, unsigned short port);


/*calc the peer id based on the string representation of the ip and
  port*/
void calc_id(char * ip, unsigned short port, char * id);

/* print info about this peer */
void print_peer(peer_t *peer);

/* check status on peers, maybe they went offline? */
int check_peer(peer_t *peer);

/*check if peers want to send me something*/
int poll_peers(bt_args_t *bt_args);

/*send a msg to a peer*/
int send_to_peer(peer_t * peer, bt_msg_t * msg);

/*read a msg from a peer and store it in msg*/
int read_from_peer(peer_t * peer, bt_msg_t *msg);


/* save a piece of the file */
int save_piece(bt_args_t * bt_args, bt_piece_t * piece);

/*load a piece of the file into piece */
int load_piece(bt_args_t * bt_args, bt_piece_t * piece);

/*load the bitfield into bitfield*/
int get_bitfield(bt_args_t * bt_args, bt_bitfield_t * bitfield);

/*compute the sha1sum for a piece, store result in hash*/
int sha1_piece(bt_args_t * bt_args, bt_piece_t * piece, unsigned char * hash);


/*Contact the tracker and update bt_args with info learned, 
  such as peer list*/
int contact_tracker(bt_args_t * bt_args);


//Gets peer handshake
void get_peer_handshake(peer_t * p, char * sha1, char * h_message);

// accept new peer
int accept_new_peer(int incoming_sockfd, char * sha1, char * h_message, char * rh_message, int * newfd, log_info * log, peer_t* peer);

int make_bitfield_msg();

#endif
