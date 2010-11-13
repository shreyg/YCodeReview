/* Filename: dr_api.c */

/* include files */
#include <arpa/inet.h>  /* htons, ... */
#include <sys/socket.h> /* AF_INET */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include<string.h>

#include "dr_api.h"
#include "rmutex.h"

/* internal data structures */
#define INFINITY 16

#define RIP_IP htonl(0xE0000009)

#define RIP_COMMAND_REQUEST  1
#define RIP_COMMAND_RESPONSE 2
#define RIP_VERSION          2

#define RIP_ADVERT_INTERVAL_SEC 10
#define RIP_TIMEOUT_SEC 20
#define RIP_GARBAGE_SEC 15

struct timeval last_advert;
struct timeval last_updated;

/*
 * Prints out IP address from integer value
 */

void advertise();

void printIPFromInt(uint32_t ip) {
	uint32_t curOctet = ip >> 24;
	fprintf(stderr, "%d.", curOctet);
	curOctet = (ip << 8) >> 24;
	fprintf(stderr, "%d.", curOctet);
	curOctet = (ip << 16) >> 24;
	fprintf(stderr, "%d.", curOctet);
	curOctet = (ip << 24) >> 24;
	fprintf(stderr, "%d\n", curOctet);
}

/** information about a route which is sent with a RIP packet */
typedef struct rip_entry_t {
	uint16_t addr_family;
	uint16_t pad;           /* just put zero in this field */
	uint32_t ip;
	uint32_t subnet_mask;
	uint32_t next_hop;
	uint32_t metric;
} __attribute__ ((packed)) rip_entry_t;

/** the RIP payload header */
typedef struct rip_header_t {
	char        command;
	char        version;
	uint16_t    pad;        /* just put zero in this field */
	rip_entry_t entries[0];
} __attribute__ ((packed)) rip_header_t;

/** a single entry in the routing table */
typedef struct route_t {
	uint32_t subnet;        /* destination subnet which this route is for */
	uint32_t mask;          /* mask associated with this route */
	uint32_t next_hop_ip;   /* next hop on on this route */
	uint32_t outgoing_intf; /* interface to use to send packets on this route */
	uint32_t cost;
	struct timeval last_updated;

	int is_garbage; /* boolean which notes whether this entry is garbage */

	route_t* next;  /* pointer to the next route in a linked-list */
} route_t;


route_t *r_table = NULL;

/* internal variables */

/* a very coarse recursive mutex to synchronize access to methods */
static rmutex_t coarse_lock;

/** how mlong to sleep between periodic callbacks */
static unsigned secs_to_sleep_between_callbacks;
static unsigned nanosecs_to_sleep_between_callbacks;


/* these static functions are defined by the dr */

/*** Returns the number of interfaces on the host we're currently connected to.*/
static unsigned (*dr_interface_count)();

/*** Returns a copy of the requested interface.  All fields will be 0 if the an* invalid interface index is requested.*/
static lvns_interface_t (*dr_get_interface)(unsigned index);

/*** Sends specified dynamic routing payload.** @param dst_ip   The ultimate destination of the packet.
 ** @param next_hop_ip  The IP of the next hop (either a router or the final dst).** @param outgoing_intf  Index of the interface to send the packet from.
 ** @param payload  This will be sent as the payload of the DR packet.  The caller*                 is reponsible for managing the memory associated with buf*                 (e.g. this function will NOT free buf).
 ** @param len      The number of bytes in the DR payload.*/
static void (*dr_send_payload)(uint32_t dst_ip,
		uint32_t next_hop_ip,
		uint32_t outgoing_intf,
		char* /* borrowed */,
		unsigned);


/* internal functions */

/* internal lock-safe methods for the students to implement */
static next_hop_t safe_dr_get_next_hop(uint32_t ip);
static void safe_dr_handle_packet(uint32_t ip, unsigned intf,
		char* buf /* borrowed */, unsigned len);
static void safe_dr_handle_periodic();
static void safe_dr_interface_changed(unsigned intf,
		int state_changed,
		int cost_changed);

/*** This simple method is the entry point to a thread which will periodically* make a callback to your dr_handle_periodic method.*/
static void* periodic_callback_manager_main(void* nil) {
	struct timespec timeout;

	timeout.tv_sec = secs_to_sleep_between_callbacks;
	timeout.tv_nsec = nanosecs_to_sleep_between_callbacks;
	while(1) {
		nanosleep(&timeout, NULL);
		dr_handle_periodic();
	}

	return NULL;
}

next_hop_t dr_get_next_hop(uint32_t ip) {
	next_hop_t hop;
	rmutex_lock(&coarse_lock);
	hop = safe_dr_get_next_hop(ip);
	rmutex_unlock(&coarse_lock);
	return hop;
}

void dr_handle_packet(uint32_t ip, unsigned intf, char* buf /* borrowed */, unsigned len) {
	rmutex_lock(&coarse_lock);
	safe_dr_handle_packet(ip, intf, buf, len);
	rmutex_unlock(&coarse_lock);
}

void dr_handle_periodic() {
	rmutex_lock(&coarse_lock);
	safe_dr_handle_periodic();
	rmutex_unlock(&coarse_lock);
}

void dr_interface_changed(unsigned intf, int state_changed, int cost_changed) {
	rmutex_lock(&coarse_lock);
	safe_dr_interface_changed(intf, state_changed, cost_changed);
	rmutex_unlock(&coarse_lock);
}


/* ****** It is recommended that you only modify code below this line! ****** */


void dr_init(unsigned (*func_dr_interface_count)(),
		lvns_interface_t (*func_dr_get_interface)(unsigned index),
		void (*func_dr_send_payload)(uint32_t dst_ip,
			uint32_t next_hop_ip,
			uint32_t outgoing_intf,
			char* /* borrowed */,
			unsigned)) {
	pthread_t tid;

	/* save the functions the DR is providing for us */
	dr_interface_count = func_dr_interface_count;
	dr_get_interface = func_dr_get_interface;
	dr_send_payload = func_dr_send_payload;

	/* initialize the recursive mutex */
	rmutex_init(&coarse_lock);

	/* initialize the amount of time we want between callbacks */
	secs_to_sleep_between_callbacks = 1;
	nanosecs_to_sleep_between_callbacks = 0;

	/* start a new thread to provide the periodic callbacks */
	if(pthread_create(&tid, NULL, periodic_callback_manager_main, NULL) != 0) {
		fprintf(stderr, "pthread_create failed in dr_initn");
		exit(1);
	}

	/* do initialization of your own data structures here */

	fprintf(stderr,"in INIT, total interfaces:  %u\n",dr_interface_count());

	uint32_t i = 1;

	for(i=1;i<=dr_interface_count();i++){

		lvns_interface_t temp = dr_get_interface(i-1);
		fprintf(stderr,"**printing interface**\n");
		printIPFromInt(ntohl(temp.ip));
		printIPFromInt(ntohl(temp.subnet_mask));
		fprintf(stderr,"Enable Status : %d and cost: %u \n",temp.enabled,temp.cost);

		// add entry to r_table, insertib at the head
		route_t* entry = (route_t*)malloc(sizeof(route_t));
		entry->subnet = temp.ip & temp.subnet_mask;
		entry->mask = temp.subnet_mask;
		entry->next_hop_ip = 0;
		entry->outgoing_intf = i-1;
		entry->cost = temp.cost;
		gettimeofday(&entry->last_updated,NULL);
		entry->is_garbage = 0;


		entry->next = r_table;
		r_table = entry;
	}

	// Do we advertise this now ? advertise()
	gettimeofday(&last_advert,NULL);
	gettimeofday(&last_updated,NULL);
	fprintf(stderr,"Sending Intialization Table Packet\n");
	advertise();
}

next_hop_t safe_dr_get_next_hop(uint32_t ip) {
	next_hop_t hop;

	hop.interface = 0;
	hop.dst_ip = 0;

	/* determine the next hop in order to get to ip */

	/* --------------------------------*/

	uint32_t longest_mask;
	longest_mask = 0;
	uint32_t  sending_iface;
	uint32_t next_hop_ip;
	route_t* table = r_table;
	int found_flag = 0;
	uint32_t cost_level = INFINITY;

	while(table){
		if(table->is_garbage){
			table = table->next;
			continue;
		}
		uint32_t  mask = (table->mask);
		if((ip & mask) == ((table->subnet) & mask) && table->cost < INFINITY){
			found_flag = 1;
			if(mask >= longest_mask){
				if(table->cost < cost_level){
				cost_level = table->cost;
				longest_mask = mask;
				sending_iface = table->outgoing_intf;
				next_hop_ip = table->next_hop_ip;
				}
			}
		}
		table = table->next;
	}

	if(!found_flag){
		hop.interface = -1;
		int index = 0;
		for(;index<4;index++){
			char* cast = (char*)(&(hop.dst_ip));
			cast[index] = -1;
		}
	}
	else{
		hop.interface = sending_iface;
		hop.dst_ip = next_hop_ip;
	}

	return hop;
}

void safe_dr_handle_packet(uint32_t ip, unsigned intf,
		char* buf /* borrowed */, unsigned len) {

	if(len < sizeof(rip_header_t)){
		fprintf(stderr, "Malformed size packet received");
		return;
	}

	int change_flag = 0;

	// If yhe interface is dead drop it.
	lvns_interface_t in_inf = dr_get_interface(intf);
	if(!in_inf.enabled){
		fprintf(stderr,"Packet arrived on a down interface\n");
		return;
	}

	/* handle the dynamic routing payload in the buf buffer */
	rip_header_t* header = (rip_header_t*)buf;
	if(header->command !=2){
		fprintf(stderr,"Dropping Packet as RIP Packet is not a  response packet \n");
		return;
	} 
	//fprintf(stderr,"The version is %d\n",header->version);

	if(ip ==0 || (int)ip == -1){
		fprintf(stderr,"Dropping Packet as UNICAST\n");
		return;
	}

	if((len - sizeof(rip_header_t))%sizeof(rip_entry_t) != 0){
		fprintf(stderr,"Packet dropped because of malformed size. Not a multiple. Length is %u\n",len);
		return;
	}

	int num_entries = (len - sizeof(rip_header_t))/sizeof(rip_entry_t);
	fprintf(stderr,"Received packets with %d enteries\n",num_entries);

	buf = buf + sizeof(rip_header_t);
	char* buf2 =(char*) header->entries;

	if(buf == buf2){
	//	fprintf(stderr,"THEY ARE SAME");
	}
	else{
	//	fprintf(stderr,"THEY ARE DIFFERENT");
	}


	uint32_t inf_cost = in_inf.cost;

	while(num_entries >0){
		rip_entry_t* entry = (rip_entry_t*)buf;	
		route_t* table = r_table;
		int flag_considered = 0;
		while(table){
			if((table->subnet == entry->ip && table->mask == entry->subnet_mask)){ // The last condition ensures that you never overwrite 
			//	fprintf(stderr,"MATCH \n");
				flag_considered = 1;
				// We have a entry for this network in table
				if(table->next_hop_ip == ip && table->cost != (entry->metric + inf_cost)){
					change_flag = 1;
					table->cost = ((entry->metric + inf_cost) < INFINITY)?entry->metric+inf_cost:INFINITY;
					struct timeval current_time;
					gettimeofday(&current_time,NULL);
					table->last_updated = current_time;
					table->is_garbage = 0;
					table->outgoing_intf = intf;
				}

				else{
					// Decide to replace on basis of cost
					if(entry->metric+inf_cost < table->cost){
						if(table->next_hop_ip == 0){
							flag_considered = 0;	
						}
						else{
						change_flag = 1;
	
						table->cost = ((entry->metric + inf_cost) < INFINITY)?entry->metric+inf_cost:INFINITY;
						struct timeval current_time;
						gettimeofday(&current_time,NULL);
						table->last_updated = current_time;
						table->outgoing_intf = intf;
						table->next_hop_ip = ip;
						table->is_garbage = 0;
						}
					}

					else if(entry->metric+inf_cost == table->cost){
						//change_flag = 1;
						 if(table->next_hop_ip == 0){                                                           /* internal variables */                
                                                        flag_considered = 0;                                                                                                   
                                                }            
						else{
						struct timeval current_time;
						gettimeofday(&current_time,NULL);
						table->last_updated = current_time;
						table->outgoing_intf = intf;
						table->next_hop_ip = ip;
						table->is_garbage = 0;
						}
					}
			

				}
				break; // We will have only one netry in table that matches exactly ??
			}		
			table = table->next;
		}

		if(!flag_considered){
			change_flag = 1;
	
			// Insert this entry into table
			fprintf(stderr,"New entry added to able after update from a packet\n");
			route_t* new_entry = (route_t*)malloc(sizeof(route_t));
			new_entry->subnet = entry->ip & entry->subnet_mask;
			new_entry->mask = entry->subnet_mask;
			new_entry->next_hop_ip = ip;
			new_entry->outgoing_intf = intf;
			new_entry->cost = ((entry->metric + inf_cost)>INFINITY)?INFINITY:(entry->metric + inf_cost);
			struct timeval current_time;
			gettimeofday(&current_time,NULL);
			new_entry->last_updated = current_time; 
			new_entry->is_garbage = 0;

			new_entry->next = r_table;
			r_table = new_entry;
		}

		num_entries--;
		buf = buf + sizeof(rip_entry_t);
	}

	if(change_flag){
	advertise();
	}
}

void safe_dr_handle_periodic() {

	struct timeval current;
	gettimeofday(&current,NULL);
	/* handle periodic tasks for dynamic routing here */
	// Make a packet for all entries and send
	route_t* table = r_table;
	route_t* prev = NULL;
	//scan the whole table remove entry if the entry has been there for 20 second, do not do it for entries whose dest_ip is 0.0.0.0

	int change_flag = 0;
	if(current.tv_sec - last_updated.tv_sec > RIP_GARBAGE_SEC){
		fprintf(stderr,"Garbage Collector activated as time elapsed was %ld\n",current.tv_sec - last_updated.tv_sec);

		while(table){
			if(table->next_hop_ip == 0){
				table = table->next;
				continue;
				// We do not timeout directly connected subnets
			}
			if((current.tv_sec - table->last_updated.tv_sec) > RIP_TIMEOUT_SEC || table->is_garbage || table->cost>=INFINITY){ //? handle is_garbage here ?
				change_flag = 1;
				// Remove this entry
				if(prev){
					prev->next = table->next;
				}
				else{
					r_table = table->next;
				}


				route_t* next = table->next;
				free(table);
				table = next;
			}
			else{
				prev = table;
				table = table->next;
			}
		}
		
		gettimeofday(&last_updated,NULL);
	}

	if(current.tv_sec - last_advert.tv_sec > RIP_ADVERT_INTERVAL_SEC){
		fprintf(stderr,"The advertise timed out after- %ld\n", current.tv_sec - last_advert.tv_sec);
		change_flag = 1;	
		gettimeofday(&last_advert,NULL);
	}

	if(change_flag){
		advertise();
	}
}

static void safe_dr_interface_changed(unsigned intf,
		int state_changed,
		int cost_changed) {
	/* handle an interface going down or being brought up */
	route_t* table = r_table;
	if(intf < 0 || intf >= dr_interface_count()){
		return;
		// Invalid intf value
	}

	int modify_flag = 0;

	while(table){
		if(table->outgoing_intf == intf){
			modify_flag = 1;
			if(cost_changed){
				if(table->next_hop_ip == 0){
					// Its a interface entry
					table->cost = (dr_get_interface(intf).cost)>INFINITY?INFINITY:(dr_get_interface(intf).cost);
				}
				else{
					table->is_garbage = 1;
				}
			}
			if(state_changed){
				table->is_garbage = !table->is_garbage;
				modify_flag = 1;
			}
		}
		table = table->next;
	}

	if(modify_flag){
		advertise();
	}
}

/* definition of internal fuinctions */

void advertise(){
	fprintf(stderr,"Enter Advertise \n");
	route_t* table = r_table;
	rip_header_t* header = (rip_header_t*)malloc(sizeof(rip_header_t));
	header->command = 2;
	header->version = 2;
	header->pad = 0;
	int size = 0;

	while(table){
		if(!table->is_garbage){
			size++;
		}
		table = table->next;
	}

	uint32_t i;

	for(i=1;i<=dr_interface_count();i++){
		lvns_interface_t intf = dr_get_interface(i-1);
		char* buff = (char*)malloc(sizeof(rip_header_t)+size*sizeof(rip_entry_t));
		memcpy(buff,header,sizeof(rip_header_t));
		char* track = buff + sizeof(rip_header_t);

		table = r_table;

		while(table){
			if(table->is_garbage){
				table = table->next;
				continue;
			}
			rip_entry_t* entry = (rip_entry_t*) malloc(sizeof(rip_entry_t));
			entry->addr_family = htons(AF_INET);
			entry->pad = 0;
			entry->ip = table->subnet;
			entry->subnet_mask = table->mask;
			entry->next_hop = table->next_hop_ip;

			if(table->outgoing_intf == i-1){
				entry->metric = INFINITY;
			}
			else{
				entry->metric = table->cost + intf.cost; //???
			}
			memcpy(track,entry,sizeof(rip_entry_t));
			track = track + sizeof(rip_entry_t);
			table = table->next;
		}
		fprintf(stderr,"Sending advertisement of len %ld from eth : %d\n",sizeof(rip_header_t)+size*sizeof(rip_entry_t),i-1);
		dr_send_payload(RIP_IP,RIP_IP,i-1,buff,sizeof(rip_header_t)+size*sizeof(rip_entry_t));
	}
		fprintf(stderr,"Exit Advertise \n");

}
