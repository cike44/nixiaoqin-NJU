/*
 * bpchat.c
 * Andrew Jenkins <andrew.jenkins@colorado.edu>
 * Reads lines from stdin and sends those in bundles.
 * Receives bundles and writes them to stdout.
 */

#include <stdlib.h>
#include <stdio.h>
#include <bp.h>

static BpSAP                sap;
static Sdr                  sdr;
static pthread_mutex_t      sdrmutex = PTHREAD_MUTEX_INITIALIZER;
static char                 *destEid = NULL;
static char                 *ownEid = NULL;
static BpCustodySwitch      custodySwitch = NoCustodyRequested;
static int                  running = 1;
static int		    controlZco;

const char usage[] =
"Usage: bpchat.c <source EID> <dest EID> [ct]\n\n"
"Reads lines from stdin and sends these lines in bundles.\n"
"Receives bundles and writes them to stdout.\n"
"If \"ct\" is specified, sent bundles have the custody transfer flag set\n";

static pthread_t    sendLinesThread;
static void *       sendLines(void *args)
{
	Object          bundleZco, bundlePayload;
	Object          newBundle;   /* We never use but bp_send requires it. */
	int             lineLength = 0;
	char            lineBuffer[5000];

	int sockfd_recv=0;
	struct sockaddr_in servaddr_recv;
	sockfd_recv=socket(AF_INET,SOCK_DGRAM,0);
	bzero(&servaddr_recv,sizeof(servaddr_recv));
	servaddr_recv.sin_family=AF_INET;
	servaddr_recv.sin_port=htons(7089);
	//host ip address
	inet_pton(AF_INET,"192.168.10.106",&servaddr_recv.sin_addr);
	bind(sockfd_recv, (struct sockaddr *)&servaddr_recv, sizeof(servaddr_recv));
	//servaddr_recv.sin_addr.s_addr=htonl(INADDR_ANY) ;
	struct sockaddr_in addr;
	socklen_t addr_len =sizeof(struct sockaddr_in);
	while(running) {
		/* Read from socket */
		bzero(lineBuffer,sizeof(lineBuffer));
		int n = recvfrom(sockfd_recv, lineBuffer, sizeof(lineBuffer), 0 , (struct sockaddr *)&addr ,&addr_len);

		printf("length = %d, data-send:\n", n);
		int i = 0;
		for(i = 0; i < n; ++i) {
			printf("%02x", lineBuffer[i]);
		}
		printf("\n");
		//printf("%s\n", lineBuffer);
		/* Read a line from stdin */
		// if(fgets(lineBuffer, sizeof(lineBuffer), stdin) == NULL) {
		// 	fprintf(stderr, "EOF\n");
		// 	running = 0;
		// 	bp_interrupt(sap);
		// 	break;
		// }

		lineLength = strlen(lineBuffer);

		/* Wrap the linebuffer in a bundle payload. */
		if(pthread_mutex_lock(&sdrmutex) != 0)
		{
			putErrmsg("Couldn't take sdr mutex.", NULL);
			break;
		}

		oK(sdr_begin_xn(sdr));
		bundlePayload = sdr_malloc(sdr, lineLength);
		if(bundlePayload) {
			sdr_write(sdr, bundlePayload, lineBuffer, lineLength);
		}

		if(sdr_end_xn(sdr) < 0) {
			pthread_mutex_unlock(&sdrmutex);
			bp_close(sap);
			putErrmsg("No space for bpchat payload.", NULL);
			break;
		}

		bundleZco = ionCreateZco(ZcoSdrSource, bundlePayload, 0, 
				lineLength, &controlZco);
		if(bundleZco == 0) {
			pthread_mutex_unlock(&sdrmutex);
			bp_close(sap);
			putErrmsg("bpchat can't create bundle ZCO.", NULL);
			break;
		}
		pthread_mutex_unlock(&sdrmutex);

		/* Send the bundle payload. */
		if(bp_send(sap, destEid, NULL, 86400, BP_STD_PRIORITY,
				custodySwitch, 0, 0, NULL, bundleZco,
				&newBundle) <= 0)
		{
			putErrmsg("bpchat can't send bundle.", NULL);
			break;
		}
	}
	return NULL;
}

static pthread_t    recvBundlesThread;
static void *       recvBundles(void *args)
{
	BpDelivery      dlv;
	ZcoReader       reader;
	char            buffer[5000];
	int             bundleLenRemaining;
	int             rc;
	int             bytesToRead;
	int sockfd_send=0;
	struct sockaddr_in servaddr_send;
	sockfd_send=socket(AF_INET,SOCK_DGRAM,0);
	bzero(&servaddr_send,sizeof(servaddr_send));
	servaddr_send.sin_family=AF_INET;
	servaddr_send.sin_port=htons(7089);
	//zhukong ip address
	inet_pton(AF_INET,"192.168.10.105",&servaddr_send.sin_addr);
	socklen_t addr_len =sizeof(struct sockaddr_in);
	while(running) {
		if(bp_receive(sap, &dlv, BP_BLOCKING) < 0)
		{
			putErrmsg("bpchat bundle reception failed.", NULL);
			break;
		}

		if(dlv.result == BpReceptionInterrupted || dlv.adu == 0) {
			bp_release_delivery(&dlv, 1);
			continue;
		}

		if(pthread_mutex_lock(&sdrmutex) != 0)
		{
			putErrmsg("Couldn't take sdr mutex.", NULL);
			break;
		}

		oK(sdr_begin_xn(sdr));
		bundleLenRemaining = zco_source_data_length(sdr, dlv.adu);
		zco_start_receiving(dlv.adu, &reader);
		while(bundleLenRemaining > 0) {
			bytesToRead = MIN(bundleLenRemaining, sizeof(buffer)-1);
			rc = zco_receive_source(sdr, &reader, bytesToRead, buffer);
			if(rc < 0) break;
			bundleLenRemaining -= rc;
			printf("length = %d, data-recv:\n", rc);
			int i = 0;
			for(i = 0; i < rc; ++i) {
				printf("%02x", buffer[i]);
			}
			printf("\n");
			//printf("%.*s", rc, buffer);
			sendto(sockfd_send,buffer,rc,0,(struct sockaddr *)&servaddr_send,addr_len);
			//fflush(stdout);
		}

		if (sdr_end_xn(sdr) < 0)
		{
			running = 0;
		}

		pthread_mutex_unlock(&sdrmutex);
		bp_release_delivery(&dlv, 1);
	}        
	return NULL;
}

void handleQuit(int sig)
{
	running = 0;
	pthread_end(sendLinesThread);
	bp_interrupt(sap);
	ionCancelZcoSpaceRequest(&controlZco);
}

int main(int argc, char **argv)
{
	ownEid      = (argc > 1 ? argv[1] : NULL);
	destEid     = (argc > 2 ? argv[2] : NULL);
	char    *ctArg = (argc > 3 ? argv[3] : NULL);

	if(argc < 2 || (argv[1][0] == '-')) {
		fprintf(stderr, usage);
		exit(1);
	}

	if(ctArg && strncmp(ctArg, "ct", 3) == 0) {
		custodySwitch = SourceCustodyRequired;
	}

	if(bp_attach() < 0) {
		putErrmsg("Can't bp_attach()", NULL);
		exit(1);
	}

	if(bp_open(ownEid, &sap) < 0) 
	{
		putErrmsg("Can't open own endpoint.", ownEid);
		exit(1);
	}

	sdr = bp_get_sdr();

	signal(SIGINT, handleQuit);

	/* Start receiver thread and sender thread. */
	if(pthread_begin(&sendLinesThread, NULL, sendLines, NULL) < 0) {
		putErrmsg("Can't make sendLines thread.", NULL);
		bp_interrupt(sap);
		exit(1);
	}

	if(pthread_begin(&recvBundlesThread, NULL, recvBundles, NULL) < 0) {
		putErrmsg("Can't make recvBundles thread.", NULL);
		bp_interrupt(sap);
		exit(1);
	}

	pthread_join(sendLinesThread, NULL);
	pthread_join(recvBundlesThread, NULL);

	bp_close(sap);
	bp_detach();
	return 0;
}
