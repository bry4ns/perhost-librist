/* PerHost single-port RIST gateway. */
#include "config.h"
#include "srp_shared.h"
#include <librist/librist.h>
#include <librist/receiver.h>
#include <librist/peer.h>
#include <librist/librist_srp.h>
#include <srt/srt.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_SESSIONS 256
#define MAX_PEERS 1024
#define MAX_QUEUE_PACKETS 512

struct packet { struct packet *next; size_t len; char data[]; };
struct session { uint32_t flow; char username[256]; SRTSOCKET srt; pthread_t writer; pthread_mutex_t lock; pthread_cond_t ready; struct packet *head, *tail; size_t queued; int closed; };
struct gateway { struct session sessions[MAX_SESSIONS]; size_t session_count; struct { struct rist_peer *peer; char username[256]; } peers[MAX_PEERS]; size_t peer_count; pthread_mutex_t lock; const char *host; int port; };
static volatile sig_atomic_t running = 1;

static void stop(int sig) { (void)sig; running = 0; }
static struct session *flow_session(struct gateway *g, uint32_t flow) { for (size_t i=0;i<g->session_count;i++) if (g->sessions[i].flow == flow) return &g->sessions[i]; return NULL; }
static const char *peer_username(struct gateway *g, struct rist_peer *peer) { for (size_t i=0;i<g->peer_count;i++) if (g->peers[i].peer == peer) return g->peers[i].username; return NULL; }

static void *writer(void *arg) {
 struct session *s = arg;
 while (!s->closed) {
  pthread_mutex_lock(&s->lock);
  while (!s->head && !s->closed) pthread_cond_wait(&s->ready, &s->lock);
  struct packet *p=s->head; if(p){s->head=p->next;if(!s->head)s->tail=NULL;s->queued--;}
  pthread_mutex_unlock(&s->lock);
  if (!p) continue;
  if (srt_sendmsg2(s->srt, p->data, (int)p->len, NULL) == SRT_ERROR) s->closed=1;
  free(p);
 }
 return NULL;
}
static int open_srt(struct gateway *g, struct session *s) {
 s->srt=srt_create_socket(); if(s->srt==SRT_INVALID_SOCK)return -1;
 int live=SRTT_LIVE; srt_setsockflag(s->srt, SRTO_TRANSTYPE, &live, sizeof(live));
 char sid[320]; snprintf(sid,sizeof(sid),"publish/live/%s",s->username); srt_setsockflag(s->srt, SRTO_STREAMID,sid,(int)strlen(sid));
 struct sockaddr_in a={0}; a.sin_family=AF_INET;a.sin_port=htons(g->port); if(inet_pton(AF_INET,g->host,&a.sin_addr)!=1 || srt_connect(s->srt,(struct sockaddr*)&a,sizeof(a))==SRT_ERROR)return -1;
 pthread_mutex_init(&s->lock,NULL); pthread_cond_init(&s->ready,NULL); return pthread_create(&s->writer,NULL,writer,s);
}
static void srp_ok(void *arg, struct rist_peer *peer, const char *username) {
 struct gateway *g=arg; pthread_mutex_lock(&g->lock); if(g->peer_count<MAX_PEERS){g->peers[g->peer_count].peer=peer;snprintf(g->peers[g->peer_count].username,256,"%s",username);g->peer_count++;} pthread_mutex_unlock(&g->lock);
}
static int allow_flow(void *arg, struct rist_peer *peer, uint32_t flow) {
 struct gateway *g=arg; pthread_mutex_lock(&g->lock); const char *u=peer_username(g,peer); struct session *s=flow_session(g,flow);
 if(!u || (s && strcmp(s->username,u)!=0) || (!s && g->session_count==MAX_SESSIONS)){pthread_mutex_unlock(&g->lock);return -1;}
 if(!s){s=&g->sessions[g->session_count++];memset(s,0,sizeof(*s));s->flow=flow;snprintf(s->username,sizeof(s->username),"%s",u);if(open_srt(g,s)){s->closed=1;pthread_mutex_unlock(&g->lock);return -1;}}
 pthread_mutex_unlock(&g->lock); return 0;
}
static int recv_data(void *arg, struct rist_data_block *b) {
 struct gateway *g=arg; pthread_mutex_lock(&g->lock); struct session *s=flow_session(g,b->flow_id); if(!s||s->closed){pthread_mutex_unlock(&g->lock);rist_receiver_data_block_free2(&b);return 0;} pthread_mutex_lock(&s->lock);pthread_mutex_unlock(&g->lock);
 if(s->queued<MAX_QUEUE_PACKETS){struct packet *p=malloc(sizeof(*p)+b->payload_len);if(p){p->next=NULL;p->len=b->payload_len;memcpy(p->data,b->payload,p->len);if(s->tail)s->tail->next=p;else s->head=p;s->tail=p;s->queued++;pthread_cond_signal(&s->ready);}} pthread_mutex_unlock(&s->lock);rist_receiver_data_block_free2(&b);return 0;
}
int main(int argc,char **argv) {
 if(argc!=5){fprintf(stderr,"usage: %s rist-url srp-file srt-host srt-port\n",argv[0]);return 2;} struct gateway g={.host=argv[3],.port=atoi(argv[4])};pthread_mutex_init(&g.lock,NULL);signal(SIGINT,stop);signal(SIGTERM,stop);srt_startup();
 struct rist_logging_settings log={0};log.log_level=RIST_LOG_INFO;struct rist_ctx *ctx;if(rist_receiver_create(&ctx,RIST_PROFILE_MAIN,&log))return 1;struct rist_peer_config *cfg=NULL;if(rist_parse_address2(argv[1],&cfg))return 1;struct rist_peer *listener;if(rist_peer_create(ctx,&listener,cfg))return 1;rist_peer_config_free2(&cfg);
 if(rist_enable_eap_srp_2(listener,NULL,NULL,user_verifier_lookup,argv[2])||rist_srp_auth_callback_set(ctx,srp_ok,&g)||rist_receiver_flow_authorize_callback_set(ctx,allow_flow,&g)||rist_receiver_data_callback_set2(ctx,recv_data,&g)||rist_start(ctx))return 1;
 while(running) sleep(1); rist_destroy(ctx); srt_cleanup(); return 0;
}
