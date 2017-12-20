/******************************************************************************
 * ctcp.c
 * ------
 * Implementation of cTCP done here. This is the only file you need to change.
 * Look at the following files for references and useful functions:
 *   - ctcp.h: Headers for this file.
 *   - ctcp_iinked_list.h: Linked list functions for managing a linked list.
 *   - ctcp_sys.h: Connection-related structs and functions, cTCP segment
 *                 definition.
 *   - ctcp_utils.h: Checksum computation, getting the current time.
 *
 *****************************************************************************/

#include "ctcp.h"
#include "ctcp_linked_list.h"
#include "ctcp_sys.h"
#include "ctcp_utils.h"

struct sendSeg {
  ctcp_segment_t *segment;
  int resend; //resend times
  long time;  //last send time, for retransmit if timeout
};
typedef struct sendSeg sendSeg_t;
/**
 * Connection state.
 *
 * Stores per-connection information such as the current sequence number,
 * unacknowledged packets, etc.
 *
 * You should add to this to store other fields you might need.
 */
 enum tcpState {
  NORM,FIN_WAIT1,FIN_WAIT2,CLOSING,TIME_WAIT,CLOSE_WAIT,LAST_ACK,CLOSED
 };
struct ctcp_state {
  struct ctcp_state *next;  /* Next in linked list */
  struct ctcp_state **prev; /* Prev in linked list */

  conn_t *conn;             /* Connection object -- needed in order to figure
                               out destination when sending */
  linked_list_t *segments;  /* Linked list of segments sent to this connection.
                               It may be useful to have multiple linked lists
                               for unacknowledged segments, segments that
                               haven't been sent, etc. Lab 1 uses the
                               stop-and-wait protocol and therefore does not
                               necessarily need a linked list. You may remove
                               this if this is the case for you */

  /* FIXME: Add other needed fields. */
  ctcp_config_t *cfg;
  uint32_t ackno;
  uint32_t seqno;
  linked_list_t *sendSegments;  //not ack send segments
  enum tcpState state;
  long time_wait; //if TIME_WAIT, save start time
  uint16_t recv_win;
  uint16_t send_win;
  unsigned char *inputBuffer; //read from stdin

  int hasPrint; //the first printf num of receive segments, a segment maybe not print one time
};
int anum=0,bnum=0;
/**
 * Linked list of connection states. Go through this in ctcp_timer() to
 * resubmit segments and tear down connections.
 */
static ctcp_state_t *state_list;

/* FIXME: Feel free to add as many helper functions as needed. Don't repeat
          code! Helper functions make the code clearer and cleaner. */


ctcp_state_t *ctcp_init(conn_t *conn, ctcp_config_t *cfg) {
  /* Connection could not be established. */
  if (conn == NULL) {
    return NULL;
  }

  /* Established a connection. Create a new state and update the linked list
     of connection states. */
  ctcp_state_t *state = calloc(sizeof(ctcp_state_t), 1);
  state->next = state_list;
  state->prev = &state_list;
  if (state_list)
    state_list->prev = &state->next;
  state_list = state;

  /* Set fields. */
  state->conn = conn;
  /* FIXME: Do any other initialization here. */

  state->cfg=cfg;
  state->seqno=1;
  state->ackno=1;
  state->segments=ll_create();
  state->sendSegments=ll_create();
  state->state=NORM;
// cfg->recv_window=5;
// cfg->send_window=5;
  state->recv_win=cfg->recv_window+1;
  state->send_win=cfg->send_window+1;
  state->inputBuffer=calloc(state->send_win,1);
  state->hasPrint=0;
  state->time_wait=0;
  return state;
}

void ctcp_destroy(ctcp_state_t *state) {
  /* Update linked list. */
  if (state->next)
    state->next->prev = state->prev;

  *state->prev = state->next;
  conn_remove(state->conn);

  /* FIXME: Do any other cleanup here. */
  //printf("closing\n");
  free(state->cfg);

  if (state->segments)
  {
    ll_node_t *curr = state->segments->head;
    ll_node_t *next = NULL;
    while (curr != NULL) {
      next = curr->next;
      ctcp_segment_t *temp =(ctcp_segment_t *)ll_remove(state->segments,curr);
      free(temp);
      curr = next;
    }
  }
  ll_destroy(state->segments);

  if (state->sendSegments)
  {
    ll_node_t *curr = state->sendSegments->head;
    ll_node_t *next = NULL;
    while (curr != NULL) {
      next = curr->next;
      sendSeg_t  *temp =(sendSeg_t  *)ll_remove(state->sendSegments,curr);
      free(temp->segment);
      free(temp);
      curr = next;
    }
  }
  ll_destroy(state->sendSegments);

  free(state->inputBuffer);
  free(state);
  end_client();
}
void sendData2(ctcp_state_t *state,ctcp_segment_t *segment) { 
   // print_hdr_ctcp(segment);
  //todo:if send error
  conn_send(state->conn,segment,ntohs(segment->len));

}
ctcp_segment_t *sendData(ctcp_state_t *state,int len,void *data,uint32_t flags) { 
  //send data, carrying ack
  ctcp_segment_t *segment=calloc(len+sizeof(ctcp_segment_t),1);
  segment->seqno=htonl(state->seqno);
  segment->ackno=htonl(state->ackno); 
  segment->len=htons(len+sizeof(ctcp_segment_t));
  segment->flags=htonl(flags|ACK);
  segment->window=htons(state->recv_win-1);
  strncpy((char*)(segment+1),(char*)data,len);
  segment->cksum=0;
  segment->cksum=cksum((void*)segment,len+sizeof(ctcp_segment_t));

  state->seqno+=len;
  
  sendData2(state,segment);
  return segment;
  // if(flags!=ACK) ll_add(state->sendSegments,segment);
}

void ctcp_read(ctcp_state_t *state) {
  /* FIXME */
  if (state->seqno>=state->send_win)  //if the send win if full
  {
    return;
  }
  if (!(state->state==NORM || state->state==CLOSE_WAIT))
  {
    return;
  }
  ctcp_segment_t *segment=NULL;

  int left=conn_input(state->conn,(void*)state->inputBuffer,state->send_win-state->seqno);
  if(left==-1) {
    segment=sendData(state,0,NULL,FIN);
    ++state->seqno;
    if(state->state==NORM)
      state->state=FIN_WAIT1;
    else if(state->state==CLOSE_WAIT) state->state=LAST_ACK;

    sendSeg_t *sendSegment=calloc(sizeof(sendSeg_t),1);
    sendSegment->resend=0;
    sendSegment->time=current_time();
    sendSegment->segment=segment;
    ll_add(state->sendSegments,sendSegment);
  }
  unsigned char *cur=state->inputBuffer;
  while(left>0) {
    int maxSend=left;
    if (maxSend>MAX_SEG_DATA_SIZE)
    {
      maxSend=MAX_SEG_DATA_SIZE;
    }
    //printf("maxsend%d %d %d %d\n",maxSend,state->left,state->send_win,state->seqno);
    segment=sendData(state,maxSend,cur,0);
    cur+=maxSend;
    left-=maxSend;

    sendSeg_t *sendSegment=calloc(sizeof(sendSeg_t),1);
    sendSegment->resend=0;
    sendSegment->time=current_time();
    sendSegment->segment=segment;
    ll_add(state->sendSegments,sendSegment);
  }
}

void processACK(ctcp_state_t *state, ctcp_segment_t *segment) {
  ll_node_t *curr = state->sendSegments->head;
  ll_node_t *next=NULL;
  while(curr!=NULL) {
    if(ntohl(((sendSeg_t *)(curr->object))->segment->seqno)<segment->ackno) {
      next=curr->next;
      sendSeg_t *sendSegment=(sendSeg_t *)ll_remove(state->sendSegments,curr);
      free(sendSegment->segment);
      free(sendSegment);
      //printf("free send\n");
      curr=next;

    }
    else break;
  }

  //printf("send length %d\n",ll_length(state->sendSegments) );
  if(ll_length(state->sendSegments)==0){
    if (state->state==LAST_ACK)
    {
      state->state=CLOSED;
    }
    else if (state->state==FIN_WAIT1)
    {
      state->state=FIN_WAIT2;
    }
    else if (state->state==CLOSING)
    {
      state->state=TIME_WAIT;
      state->time_wait=current_time();
    }
  }
  if(state->state==CLOSED && ll_length(state->segments)==0) {
    free(segment);
    ctcp_destroy(state);   
  }
}

void sortAdd(linked_list_t *segments,ctcp_segment_t *segment) {
  if(ll_length(segments)==0) ll_add(segments,segment);
  else {
    ll_node_t *curr = segments->head;
    ll_node_t *next =NULL;
    if (segment->seqno<((ctcp_segment_t *)curr->object)->seqno)
    {
      ll_add_front(segments,segment);
    }
    else {
      uint32_t seqno;
      while (curr != NULL) {
        next=curr->next;
        seqno=((ctcp_segment_t *)next->object)->seqno;
        if(seqno>segment->seqno) break;
        curr = next;
      }
      if(seqno>segment->seqno) {
        ll_add_after(segments,curr,segment);
      }
      else if(curr==NULL) ll_add_after(segments,ll_back(segments),segment);
      else{
        free(segment);
      }
    }
  }
  
  
}
void processData(ctcp_state_t *state, ctcp_segment_t *segment) {
  if (state->ackno>segment->seqno)
  {
    free(segment);
    return;
  }
  sortAdd(state->segments,segment); //put received segment orderly
  //printf("recv length %d\n",ll_length(state->segments) );
  ctcp_segment_t *temp=NULL;
  ll_node_t *curr = state->segments->head;
  while(curr!=NULL) {
    temp=((ctcp_segment_t *)curr->object);
    if(state->ackno==temp->seqno) {
      state->ackno+=temp->len;
      if(temp->len==0) ++state->ackno;
    }
    else break;
    curr=curr->next;
  }
  if (temp->len==0)
  {
    if(state->state==NORM)
      state->state=CLOSE_WAIT;
    else if(state->state==FIN_WAIT2) {
      state->state=TIME_WAIT;
      state->time_wait=current_time();
    }
    else if(state->state==FIN_WAIT1)
      state->state=CLOSING;
  }
  // temp=sendData(state,0,NULL,ACK);
  // free(temp);
  ctcp_output(state);
}
void processFIN(ctcp_state_t *state, ctcp_segment_t *segment) {
  processData(state,segment);
}
bool isCorrect(ctcp_segment_t *segment, size_t len) {
  int plen=ntohs(segment->len);
  if (plen>len || cksum((void*)segment,plen)!=0xffff)
  {
    return false;
  }
  else return true;
}
void convertPacket(ctcp_segment_t *segment) {
  segment->seqno=ntohl(segment->seqno);
  segment->ackno=ntohl(segment->ackno);
  segment->len=ntohs(segment->len)-sizeof(ctcp_segment_t);
  segment->flags=ntohl(segment->flags);
  segment->window=ntohs(segment->window);

}
void ctcp_receive(ctcp_state_t *state, ctcp_segment_t *segment, size_t len) {
  /* FIXME */
    // print_hdr_ctcp(segment);
  if(isCorrect(segment,len)) {
    convertPacket(segment);
    state->send_win=segment->window+1;
    if ((segment->flags& ACK)!=0)
    {
      processACK(state,segment);
    }
    if ((segment->flags & FIN)!=0)
    {
      processFIN(state,segment);
    }
    else if(segment->len>0 && (state->state==NORM||state->state==FIN_WAIT1||state->state==FIN_WAIT2)) processData(state,segment);
    else {free(segment);}
  }
  else {free(segment);}
}

void ctcp_output(ctcp_state_t *state) {
  /* FIXME */
  size_t size=conn_bufspace(state->conn);
  if(size<=0) return;
  ctcp_segment_t *temp=NULL;
  ll_node_t *curr = state->segments->head;
  ll_node_t *next = NULL;
  int len=0;
  while(curr!=NULL) {
    temp=((ctcp_segment_t *)curr->object);
    next=curr->next;
    if(state->ackno>=temp->seqno && size>0) {
      len=temp->len-state->hasPrint;
      if (len>size)
      {
        len=size;
      }
      //printf("out %d %d %d\n",len,temp->len,state->hasPrint);
      conn_output(state->conn,temp->data+state->hasPrint,len);
      if(len==temp->len-state->hasPrint) {   
        //printf("free recv\n");
        state->hasPrint=0;  
        state->recv_win+=temp->len;
        free(sendData(state,0,NULL,ACK));

        ll_remove(state->segments,curr); 
        free(temp);

        if(len==0) break;           
      }
      else state->hasPrint+=len;
      curr=next;
      size-=len;
      
    }
    else break;
  } 
  
  if (len==0)
  {
    ll_node_t *curr = state->segments->head;
    ll_node_t *next = NULL;
    while (curr != NULL) {
      next = curr->next;
      ctcp_segment_t *temp =(ctcp_segment_t *)ll_remove(state->segments,curr);
      free(temp);

      curr = next;
    }
    // ll_destroy(state->segments);
  }
  //printf("recv length %d\n",ll_length(state->segments) );
  if (len==0&&state->state==CLOSED)
  {
    ctcp_destroy(state);
  }
}

void ctcp_timer() {
  /* FIXME */
  if (state_list)
  {
    ctcp_state_t *curr = state_list;
    ctcp_state_t *next=NULL;
    long time=current_time();
    while (curr != NULL) {
      next=curr->next;
      if (curr->state==TIME_WAIT) //close TIME_WAIT
      {
        if (time-curr->time_wait>curr->cfg->rt_timeout)
        {
          ctcp_destroy(curr);
        }        
      }
      else {
        ll_node_t *cur2 = curr->sendSegments->head;
        while (cur2 != NULL) {
          sendSeg_t  *temp =(sendSeg_t  *)(cur2->object);
          
          if (temp->resend==5)
          {
            curr->state=CLOSED;
            ctcp_destroy(curr);
            break;
          }
          if (time-temp->time>curr->cfg->rt_timeout)
          {
            ++temp->resend;
            temp->time=time;
            sendData2(curr,temp->segment);
          }
          cur2 = cur2->next;
        }
      }

      curr=next;
    }
  }
}
