 #ifndef CLOUD_CONFIG_H
#define CLOUD_CONFIG_H

//#define MANAGER_HOST_ADDR  "10.0.0.2"
//#define MANAGER_ADDR  "172.21.5.8"
#define MANAGER_ADDR  "172.21.6.78"
#define VERIFIER_ADDR  "172.21.4.160"
#define LOCAL_ADDR "127.0.0.1"
//#define VERIFIER_ADDR  "10.0.0.3"
#define HOST_ADDR  "172.21.5.8"

#define LISTEN_ADDR  "0.0.0.0"
//#define CLOUD_LOCAL_TEST

static char local_trust_addr[] = LOCAL_ADDR ":12910";
static char local_center_addr[] = LOCAL_ADDR ":12920";
static char local_manager_addr[] = LOCAL_ADDR ":12930";
static char ca_addr[] = LOCAL_ADDR ":12999";
static char local_jsonserver_addr[] = MANAGER_ADDR ":12888";

#ifdef  CLOUD_LOCAL_TEST
static char center_trust_addr[] = LOCAL_ADDR ":12980";
static char center_ca_addr[] = LOCAL_ADDR ":12581";
static char verifier_addr[] = LOCAL_ADDR ":12810";
static char host_trust_addr[] = LOCAL_ADDR ":12820";
#else
static char center_trust_addr[] = HOST_ADDR ":12980";
//static char center_ca_addr[] = MANAGER_ADDR ":12581";
static char center_ca_addr[] = HOST_ADDR ":12581";
static char verifier_addr[] = VERIFIER_ADDR ":12810";
static char host_trust_addr[] = HOST_ADDR ":12820";
#endif
static char server_addr[] = LOCAL_ADDR ":12682";
static char server_port[] = "12682";
static char vm_port[] = "12782";
static char endpoint_port[] = "12882";

static struct timeval time_val={0,50*1000};
#endif // CLOUD_CONFIG_H
