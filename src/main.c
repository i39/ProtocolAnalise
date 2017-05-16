#include"ProtocolAnalyse.h"
//#include<signal.h>
//#include<sys/time.h>
//#include<unistd.h>

//#define SIZEOF_ID_STRUCT (sizeof(struct ndpi_id_struct))
//struct ndpi_flow_struct *ndpi_flow;
//void *src,*dst;


//FILE* fd;
//MYSQL *mysql;

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



//void open_mysql()
//{
//	//char create[]="create table FlowAnalyse(PrivateIP varchar(30),ExplicitIP varchar(30),PrivatePort int,ExplicitPort int,TransportProtocol varchar(30),ApplicationProtocol varchar(30),BeginTime varchar(30),EndTime varchar(30),Flow int,Packets int);";
//	if((mysql=mysql_init(NULL))==NULL)
//		printf("init failed\n");
//	if(NULL == mysql_real_connect(mysql,"localhost","root","root","mydatabase",0,NULL,0))
//		printf("connect failed\n");
//	/*if(mysql_real_query(mysql,create,strlen(create))!=0)
//		printf("create failed\n");
//	*/
//}


int main()
{
	//const char* 
	//fd=fopen("log","w");
	//printf("main id=%lu\n",pthread_self());
	pthread_mutex_init(&lock,NULL);
	struct pcap_t *device = open_pcapdevice();
	
	//init ndpi struct
	setup_detection(device);


	//open_mysql();

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
