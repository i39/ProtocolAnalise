#include<stdio.h>
#include<stdlib.h>
#include<pcap/pcap.h>
#include"libndpi-1.8.0/libndpi/ndpi_main.h"
#include"libndpi-1.8.0/libndpi/ndpi_api.h"
#include<signal.h>
#include<sys/time.h>
#include<pthread.h>

#define IP_MF 0x2000     //0010 0000 0000 0000
#define IP_OFFSET 0x1fff    //offset part
#define SNAP 0xaa

//main struct 
struct ndpi_workflow
{
	//u_int32_t last time;
	pcap_t *handle;
	struct ndpi_detection_module_struct *ndpi_struct;
	void **ndpi_flow_root; 
};


//ndpi flow infstruct
struct ndpi_flow_info
{
	u_int32_t src;
	u_int32_t dst;
	char lower_ip[48],upper_ip[48];
	u_int16_t sport;
	u_int16_t dport;
	u_int8_t detection_completed, protocol;
	struct ndpi_flow_struct *ndpi_flow;
	ndpi_protocol detected_protocol;
	void *src_id,*dst_id;
	u_int32_t packets;
	int data_len;
	struct timeval begin,end;
};


//Open Device
struct pcap_t* open_pcapdevice();

//Setup the ndpi arguments
void setup_detection(struct pcap_t *handle);

//Run pcap_loop
void run_pcaploop(struct pcap_t *device);

//pcap_loop call back
void packet_analyse(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet);

//get protocol func
void get_protocol(struct ndpi_iphdr *hdr,u_int16_t ip_offset,u_int32_t ip_size);

//init workflow
void ndpi_workflow_init(pcap_t *handle);

//get_ndpi_flow_info
struct get_ndpi_flow_info *get_nepi_flow_info(struct ndpi_iphdr *iph,u_int16_t ip_offset,struct ndpi_id_struct **src,struct ndpi_id_struct **dst);

//ndpi_node_com
int ndpi_node_com(const void *a,const void *b);






//pthread
void init_time();
void init_sigaction();
void thread_fun(void *arg);
void do_timeout();
void prevorder_tree(ndpi_node *root);
void check_node(ndpi_node *root);

