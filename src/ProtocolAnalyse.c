#include"ProtocolAnalyse.h"
#include"trace.h"
//#include<sys/types.h>
#include<sys/syscall.h>


#define TIMEOUT 101
#define INTERVAL 20   //time lag 
#define HASH_SIZE 64
#define NUM_ROOTS 512
#define SIZEOF_FLOW_STRUCT (sizeof(struct ndpi_flow_struct))
#define SIZEOF_ID_STRUCT (sizeof(struct ndpi_id_struct))
#define IPFRAG_HIGH_THRESH            (256*1024)
#define IPFRAG_LOW_THRESH            (192*1024)
#define IP_FRAG_TIME     (30 * 1000)   /* fragment lifetime */



//pid_t gettid()
//{
//	return syscall(SYS_gettid);
//}



extern pthread_mutex_t lock;
//extern MYSQL* mysql;
extern FILE* fd;
//memory counters
u_int32_t current_ndpi_memory=0,max_ndpi_memory=0;

//declare main flow
struct ndpi_workflow *main_workflow;



void check_node(ndpi_node *root)
{

	struct ndpi_flow_info *tmpnode;
	tmpnode=(struct ndpi_flow_info*)(root->key);
	int node_timeout;
	struct timeval com_time;
	//printf("start:%d\n",tmpnode->begin.tv_sec);
	//fclose(fd);	
	//printf("end:%d\n",tmpnode->end.tv_sec);
	gettimeofday(&com_time,NULL);
	//printf("now:%d\n",com_time.tv_sec);
	node_timeout=com_time.tv_sec-tmpnode->end.tv_sec;
	//printf("time=%d\n",node_timeout);
	if((/*(node_timeout >= TIMEOUT) &&*/ (tmpnode->detection_completed == 1)))
	{
		Trace("write data to database\n");
		char data[512];
		char buf[64];
		ndpi_protocol2name(main_workflow->ndpi_struct,tmpnode->detected_protocol,buf,sizeof(buf));
		Trace("buf=%s",buf);
		sprintf(data,"insert into FlowAnalyse(PrivateIP,ExplicitIP,PrivatePort,ExplicitPort,TransportProtocol,ApplicationProtocol,BeginTime,EndTime,Flow,Packets)values('%s','%s',%d,%d,%d,'%s','%s','%s',%d,%d)",tmpnode->lower_ip,tmpnode->upper_ip,\
			tmpnode->sport,tmpnode->dport,(tmpnode->protocol),buf,ctime(&(tmpnode->begin.tv_sec)),\
			ctime(&(tmpnode->end.tv_sec)),tmpnode->data_len,tmpnode->packets);
		Trace("%s\n",data);
	//insert_mysql(mysql,data);
	}
}


void prevorder_tree(ndpi_node *root)
{
	if(root!=(ndpi_node*)0)
	{
		check_node(root);
		prevorder_tree(root->left);
		prevorder_tree(root->right);
	}
}

void do_timeout()
{
	//  use main_workflow->ndpi_flow_root  
	//printf("do timeout\n");
	pthread_mutex_lock(&lock);
	int i=0;
	struct ndpi_node** root;
	for(;i<NUM_ROOTS;i++)
	{
		root =((ndpi_node**)(&(main_workflow->ndpi_flow_root[i])));
		if(root==(ndpi_node**)0)
			continue;
		if(*root != (ndpi_node*)0)
		{
		//	printf("%x\n",root);
		//	printf("idx(i)=%d\n",i);
			prevorder_tree(*root);
		}
	}
	pthread_mutex_unlock(&lock);
}

void init_sigaction()
{
	struct sigaction tact;
	tact.sa_handler=do_timeout;
	tact.sa_flags=0;

	sigemptyset(&tact.sa_mask);

	sigaction(SIGALRM,&tact,NULL);
}

void init_time()
{
	struct itimerval value;
	value.it_value.tv_sec = INTERVAL;
	value.it_value.tv_usec=0;
	//gettimeofday(&(value.it_interval));
	value.it_interval=value.it_value;
	setitimer(ITIMER_REAL,&value,NULL);
}

void thread_fun(void *arg)
{
	//Trace("%d\n",gettid());
	init_sigaction();
	init_time();
	while(1)
		;
}


/* ******************************************* */
/*             open pcap device                */
/* ******************************************* */
struct pcap_t* open_pcapdevice()
{
	char errBuf[PCAP_ERRBUF_SIZE];
    //, *devStr;
	//devStr = "eth2";

	struct pcap_t *handle = NULL;
	char file[]="3.pcap";
    handle=pcap_open_offline(file,errBuf);

	if(handle == NULL)
	{
		printf("error opening file 3.pcap\n");
        exit(0);
	}
//	handle = pcap_open_live(devStr, 65535, 1, 0, errBuf);
//	if (handle)
//	{
//		printf("open sucess\n");
//	}
//	else
//	{
//		printf("open failed\n");
//		exit(0);
//	}
//
	return handle;
}


/* ******************************************* */
/*      set ndpi protocol and arguments        */
/* ******************************************* */
void setup_detection(struct pcap_t *handle)
{
	NDPI_PROTOCOL_BITMASK all;
	ndpi_workflow_init(handle);
	main_workflow->ndpi_struct->http_dont_dissect_response=0;
	main_workflow->ndpi_struct->dns_dissect_response=0;
	NDPI_BITMASK_SET_ALL(all);
	ndpi_set_protocol_detection_bitmask2(main_workflow->ndpi_struct,&all);
}



/* ******************************************* */
/*                  RunPcapLoop                */
/* ******************************************* */
void run_pcaploop(struct pcap_t *handle)
{
	pcap_loop(handle, -1, packet_analyse,(u_char*)handle);
}


/* ******************************************* */
/*     call back packet analyse                */
/* ******************************************* */
void packet_analyse(u_char *user,const struct pcap_pkthdr *hdr,const u_char *packet)
{
	//int i =0;
	/*for(i=0;i<hdr->len;++i)
	{
		printf("%02x ",packet[i]);
	}
	printf("\n");*/
	


	//only deal with DLT_EN10MB
	const struct ndpi_ethhdr *ethernet;
	//llc header
	const struct ndpi_llc_header *llc;
	//ip header
	struct ndpi_iphdr *iph;

	u_int16_t eth_offset = 0;
	u_int16_t ip_offset = 0;
	u_int16_t type = 0;
	int pyld_eth_len = 0;
	int check = 0;
	int flag = 0;
	//ndpi_protocol  protocol;
	//u_char *packet_check=malloc(hdr->caplen);
	//memcpy(packet_check,packet,hdr->caplen);
	//system("pause");
	const int eth_type = pcap_datalink((struct pcap*)user);
	switch(eth_type)
	{
		/* IEEE 802.3 Ethernet */
		case DLT_EN10MB:
			ethernet = (struct ndpi_ethhdr*)&packet[eth_offset];
			ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;


			check = ntohs(ethernet->h_proto);
			/* debug print */
			//printf("%d\n",check);
			if(check <= 1500)  //length of data frame
				pyld_eth_len = check;

			else if(check >= 1536) //type
				type = check;
			if(pyld_eth_len != 0)
				{
				if(packet[ip_offset] == SNAP)
					{
						printf("llc\n");
						llc = (struct ndpi_llc_header*)&(packet[ip_offset]);
						//type = llc->snap.proto_ID;
						ip_offset += 8;
					}
				}
		break;
		default:
			printf("Unknow link type\n");
		break;
	}
	//printf("type=%d\n",type);
	/* already get ip packet*/
	iph = (struct ndpi_iphdr*)&(packet[ip_offset]);
	/*if(iph->protocol == IPPROTO_UDP)
	{
		printf("UDP\n");
	}*/
	flag = ntohs(iph->frag_off);

//	printf("TOT_LEN = %d ",ntohs(iph->tot_len));
//	printf("DF = %d ",flag & 0x4000);
//	printf("MF = %d ",flag & IP_MF);
//	printf("OFFSET = %d\n",flag & IP_OFFSET);

	//not ip fragments
	if(((flag & IP_MF) == 0) && ((flag & IP_OFFSET) == 0))
	{
		get_protocol(iph,ip_offset,hdr->len-ip_offset);
		//printf("is not fragments\n");
		//if(protocol.master_protocol!=0)
		//printf("%d\n",protocol.master_protocol);
	}
	else
	{
		//iph = get_whole_ip_packet(iph);
		if(iph)
		{
		}
		else
		{
			return ;
		}
	}
	return ;
}






/* ******************************************* */
/*             ndpi_node_com                   */
/* ******************************************* */
int ndpi_node_com(const void *a,const void *b)
{
	struct ndpi_flow_info *fa = (struct ndpi_flow_info*)a;
	struct ndpi_flow_info *fb = (struct ndpi_flow_info*)b;
	if(fa->src < fb->src)
		return (-1);
	else
	{
		if(fa->src > fb->src)
			return (1);
	}
	if(fa->dst < fb->dst)
		return (-1);
	else
	{
		if(fa->dst > fb->dst)
			return (1);
	}
	if(fa->sport < fb->sport)
		return (-1);
	else
	{
		if(fa->sport > fb->sport)
			return (1);
	}
	if(fa->dport < fb->dport)
		return (-1);
	else
	{
		if(fa->dport > fb->dport)
			return (1);
	}
	if(fa->protocol < fb->protocol)
		return (-1);
	else
	{
		if(fa->protocol > fb->protocol)
			return (1);
	}
	return 0;
}




/* ******************************************* */
/*          get_ndpi_flow_info                */
/* ******************************************* */
struct ndpi_flow_info *get_ndpi_flow_info(struct ndpi_iphdr *iph,u_int16_t ip_offset,struct ndpi_id_struct **src,struct ndpi_id_struct **dst)
{
	struct ndpi_tcphdr *tcph;
	struct ndpi_udphdr *udph;
	u_int32_t saddr,daddr,addr_tmp;
	u_int16_t sport,dport,port_tmp;
	u_int32_t ip_header_len;
	u_int8_t protocol;
	u_int32_t idx;
	struct ndpi_flow_info flow;
	void *ret;
	struct timeval write_time;

	gettimeofday(&write_time,NULL);
	protocol = iph->protocol;
	ip_header_len = (iph->ihl)*4;
	saddr = iph->saddr;
	daddr = iph->daddr;

	//TCP
	if(protocol == IPPROTO_TCP)
	{
		tcph = (struct ndpi_tcphdr*)&(iph[ip_header_len]);
		sport = ntohs(tcph->source);
		dport = ntohs(tcph->dest);
	}
	//UDP
	else if(protocol == IPPROTO_UDP)
	{
		udph = (struct ndpi_udphdr*)&(iph[ip_header_len]);
		sport = ntohs(udph->source);
		dport = ntohs(udph->dest);
	}
	else
	{
		sport = 0;
		dport = 0;
	}
	//use lower 
	if(saddr > daddr)
	{
		addr_tmp = saddr;
		saddr = daddr;
		daddr = addr_tmp;
		port_tmp = sport;
		sport = dport;
		dport = port_tmp;
	}


	flow.src = saddr;
	flow.dst = daddr;
	flow.sport = sport;
	flow.dport = dport;
	flow.protocol = protocol;

	idx = (saddr + daddr + sport + dport + protocol)%NUM_ROOTS;
	//printf("result=%ld\n",saddr+daddr+sport+dport+protocol);	
	//printf("nodeidx=%d\n",idx);

	ret = ndpi_tfind(&flow,&main_workflow->ndpi_flow_root[idx],ndpi_node_com);
	if(ret == NULL)
	{
	//	printf("ret==NULL\n");
		struct ndpi_flow_info *newflow = (struct ndpi_flow_info *)malloc(sizeof(struct ndpi_flow_info));
		if(newflow == NULL)
		{
			printf("memory failed!\n");
			return 0;
		}
		memset(newflow,0,sizeof(struct ndpi_flow_info));
		newflow->src=saddr;
		newflow->dst=daddr;
		newflow->sport=sport;
		newflow->dport=dport;
		newflow->protocol=protocol;
		newflow->data_len=iph->tot_len-ip_header_len;
		newflow->begin=write_time;
		newflow->end=write_time;

		//printf("beginwrite:%d\n",newflow->begin.tv_sec);
		//printf("endwrite:%d\n",newflow->end.tv_sec);
		
		inet_ntop(AF_INET,&saddr,newflow->lower_ip,sizeof(newflow->lower_ip));
		inet_ntop(AF_INET,&daddr,newflow->upper_ip,sizeof(newflow->upper_ip));

		if((newflow->ndpi_flow = ndpi_malloc(SIZEOF_FLOW_STRUCT)) == NULL)
		{
			free(newflow);
			return NULL;
		}
		else
			memset(newflow->ndpi_flow,0,SIZEOF_FLOW_STRUCT);
		if((newflow->src_id = ndpi_malloc(SIZEOF_ID_STRUCT)) == NULL) 
		{
			free(newflow);
			return NULL;
		}
		else
			memset(newflow->src_id,0,SIZEOF_ID_STRUCT);
		if((newflow->dst_id = ndpi_malloc(SIZEOF_ID_STRUCT)) == NULL)
		{
			free(newflow);
			return NULL;
		}
		else
			memset(newflow->dst_id,0,SIZEOF_ID_STRUCT);
		ndpi_tsearch(newflow, &main_workflow->ndpi_flow_root[idx], ndpi_node_com);
		*src = newflow->src_id;
		*dst = newflow->dst_id;
		return newflow;
	}
	else
	{
		struct ndpi_flow_info *tmpflow = *(struct ndpi_flow_info**)ret;
		if(tmpflow->src == saddr && tmpflow->dst == daddr && tmpflow->sport == sport && tmpflow->dport == dport && tmpflow->protocol == protocol)
		{
			*src = tmpflow->src_id;
			*dst = tmpflow->dst_id;
		}
		else
		{
			*src = tmpflow->dst_id;
			*dst = tmpflow->src_id;
		}
		tmpflow->data_len+=(iph->tot_len-ip_header_len);
		tmpflow->end=write_time;
		//printf("%x\n",&tmpflow);
		return tmpflow;
	}
}



/* ******************************************* */
/*            get protocol func                */
/* ******************************************* */
void get_protocol(struct ndpi_iphdr *iph,u_int16_t ip_offset,u_int32_t ip_size)
{
	char buf[64];
	struct ndpi_flow_info *flow = NULL;
	struct ndpi_flow_struct *ndpi_flow = NULL;
	struct ndpi_id_struct *src, *dst;
	if(iph)
	{
		pthread_mutex_lock(&lock);
		flow = get_ndpi_flow_info(iph,ip_offset,&src,&dst);
	}
	else
	{
		//ipv6
	}
	if(flow != NULL)
	{
		flow->packets++;
		ndpi_flow = flow->ndpi_flow;
	}
	else
	{
		pthread_mutex_unlock(&lock);
		return;
	}
	if(flow->detection_completed)
	{
		pthread_mutex_unlock(&lock);
		return;
	}
	flow->detected_protocol= ndpi_detection_process_packet(main_workflow->ndpi_struct,ndpi_flow,(u_char *)iph,ip_size,1000,src,dst);
	if((flow->detected_protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN) || ((flow->protocol == IPPROTO_UDP) && (flow->packets > 8)) || ((flow->protocol==IPPROTO_TCP) && (flow->packets > 10)))
	{
		flow->detection_completed=1;
	}
	if(flow->detection_completed)
	{
		if(flow->detected_protocol.master_protocol == NDPI_PROTOCOL_UNKNOWN)
		{
			flow->detected_protocol=ndpi_detection_giveup(main_workflow->ndpi_struct,flow->ndpi_flow);
		}
	}
	pthread_mutex_unlock(&lock);
	
	
	ndpi_protocol2name(main_workflow->ndpi_struct,flow->detected_protocol,buf,sizeof(buf));
	printf("%s\n",buf);
}


/* ******************************************* */
/*           ndpi_workflow_init                */
/* ******************************************* */
static void *malloc_wrapper(size_t size)
{
	current_ndpi_memory +=size;
	if(current_ndpi_memory > max_ndpi_memory)
		max_ndpi_memory = current_ndpi_memory;
	return malloc(size);
}

static void free_wrapper(void *freeable)
{
	free(freeable);
}

void ndpi_workflow_init(pcap_t *handle)
{
	set_ndpi_malloc(malloc_wrapper),set_ndpi_free(free_wrapper);
	struct ndpi_detection_module_struct *module = ndpi_init_detection_module();
	main_workflow = calloc(1,sizeof(struct ndpi_workflow));
	main_workflow->handle = handle;
	main_workflow->ndpi_struct = module;
	main_workflow->ndpi_flow_root = calloc(NUM_ROOTS,sizeof(void*));
	if(main_workflow->ndpi_struct == NULL)
	{
		exit(-1);
	}
	//memset(&(main_workflow->ndpi_flow_root),0,sizeof(void*)*NUM_ROOTS);
}

