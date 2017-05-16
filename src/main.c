#include"ProtocolAnalyse.h"
//#include<signal.h>
//#include<sys/time.h>
//#include<unistd.h>

//#define SIZEOF_ID_STRUCT (sizeof(struct ndpi_id_struct))
//struct ndpi_flow_struct *ndpi_flow;
//void *src,*dst;


//FILE* fd;

pthread_mutex_t lock;

void thread_create()
{
	pthread_t pid;
	int ret;
	if((ret=pthread_create(&pid,NULL,(void*)thread_fun,NULL))==-1)
	{
		perror("pthread failed");
		exit(EXIT_FAILURE);
	}
}





int main()
{
	//const char* 
	//fd=fopen("log","w");
	//printf("main id=%lu\n",pthread_self());
	pthread_mutex_init(&lock,NULL);
	struct pcap_t *device = open_pcapdevice();
	
	//init ndpi struct
	setup_detection(device);



	//timeout system
	//init_sigaction();
	//init_time();
	
	
	thread_create();
	//run pcap_loop
	run_pcaploop(device);
	
	pthread_exit(NULL);	
	//fclose(fd);
	return 0;
}
