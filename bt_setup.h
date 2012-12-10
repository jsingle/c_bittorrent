#ifndef _BT_SETUP_H
#define _BT_SETUP_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "bt_lib.h"
#include "bencode.h"


/**
 * __parse_peer(peer_t * peer, char peer_st) -> void
 *
 * parse a peer string, peer_st and store the parsed result in peer
 *
 * ERRORS: Will exit on various errors
 **/
void usage(FILE * file);


/**
 * pars_args(bt_args_t * bt_args, int argc, char * argv[]) -> void
 *
 * parse the command line arguments to bt_client using getopt and
 * store the result in bt_args.
 *
 * ERRORS: Will exit on various errors
 *
 **/

void parse_args(bt_args_t * bt_args, int argc,  char ** argv);

void print_args(bt_args_t * bt_args);

void setup_peer_bitfields(char * sha1, piece_tracker * piece_track, char * h_message, char * rh_message);

/**
 * if peers are specified, try to connect to them
 */
int connect_to_peer(peer_t * peer, char * sha1, char * h_message, char * rh_message,int * sfd);

int read_handshake(int peer_sock_fd,char * rh_message,char * h_message);

int init_incoming_socket(int port);

FILE * process_savefile(bt_args_t *,bt_info_t *,piece_tracker *);

void init_piece_tracker(piece_tracker * pt,bt_info_t * track_nfo);

#endif
