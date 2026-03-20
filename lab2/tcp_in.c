#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>
// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u16 old_snd_wnd = tsk->snd_wnd;
	tsk->snd_wnd = cb->rwnd;
	if (old_snd_wnd == 0)
		wake_up(tsk->wait_send);
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt))
		tcp_update_window(tsk, cb);
}

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	if (less_than_32b(cb->seq, rcv_end) && less_or_equal_32b(tsk->rcv_nxt, cb->seq_end)) {
		return 1;
	}
	else {
		log(ERROR, "received packet with invalid seq, drop it.");
		return 0;
	}
}

// Process the incoming packet according to TCP state machine. 
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	switch(tsk->state){
		case TCP_CLOSED:
			log(ERROR, "received packet for closed socket, drop it.");
			tcp_send_reset(cb);
			break;
	//三次握手过程
		//第一次握手
		case TCP_LISTEN:{
			if(cb->flags & TCP_SYN){
				log(DEBUG,"第一次握手");
				//建立子sock，
				struct tcp_sock *new_tsk = alloc_tcp_sock();
				new_tsk->parent = tsk;
				new_tsk->sk_dip = cb->saddr;
				new_tsk->sk_dport = cb->sport;
				new_tsk->sk_sip = cb->daddr;
				new_tsk->sk_sport = tsk->sk_sport;

				new_tsk->iss = tcp_new_iss();
				new_tsk->snd_nxt = new_tsk->iss;
				new_tsk->rcv_nxt = cb->seq + 1;

				//加入listen队列，发送SYN+ACK报文，状态转为SYN_RECV，并加入哈希表
				list_add_tail(&new_tsk->list, &tsk->listen_queue);
				tcp_send_control_packet(new_tsk, TCP_SYN|TCP_ACK);
				tcp_set_state(new_tsk, TCP_SYN_RECV);
				tcp_hash(new_tsk);
			}
			else{
				log(ERROR, "received non-SYN packet in LISTEN state, drop it.");
				tcp_send_reset(cb);
			}
			break;
		}
		//第二次握手
		case TCP_SYN_SENT:{
			if(cb->flags & TCP_SYN && cb->flags & TCP_ACK){
				log(DEBUG,"第二次握手");
				if(cb->ack == tsk->iss + 1){
					tsk->rcv_nxt = cb->seq + 1;
					tcp_send_control_packet(tsk, TCP_ACK);
					tcp_set_state(tsk, TCP_ESTABLISHED);
					wake_up(tsk->wait_connect);
				}
				else{
					log(ERROR, "received ACK with wrong ack number, drop it.");
				}
			}
			else if(cb->flags & TCP_SYN){
				tsk->rcv_nxt = cb->seq + 1;
				tcp_send_control_packet(tsk, TCP_ACK);
			}
			else{
				log(ERROR, "received packet with wrong flags in SYN_SENT state, drop it.");
			}
			break;
		}
		//第三次握手
		case TCP_SYN_RECV:{
			if(cb->flags & TCP_ACK){
				if(cb->ack == tsk->iss + 1){
					log(DEBUG,"第三次握手");
					tcp_sock_accept_enqueue(tsk);
					tcp_set_state(tsk, TCP_ESTABLISHED);
					wake_up(tsk->parent->wait_accept);
				}
				else{
					log(ERROR, "received ACK with wrong ack number, drop it.");
				}
			}
			break;
		}
		case TCP_ESTABLISHED:{
			/* if(cb->flags & TCP_ACK){
				tcp_update_window_safe(tsk, cb); }*/
			if(cb->flags & TCP_FIN){
				log(DEBUG,"收到FIN报文,准备第二次挥手");
				tsk->rcv_nxt = cb->seq + 1;
				/* wait_exit(tsk->wait_recv);
				wait_exit(tsk->wait_send); */
				tcp_send_control_packet(tsk, TCP_ACK);
				tcp_set_state(tsk, TCP_CLOSE_WAIT);
			}
			break;
		}
		case TCP_FIN_WAIT_1:{
			if(cb->flags & TCP_ACK && cb->flags & TCP_FIN){
				log(DEBUG,"同时收到收到ACK和FIN报文,直接进入TCP_TIME_WAIT状态");
				tcp_send_control_packet(tsk, TCP_ACK);
				tcp_set_state(tsk, TCP_TIME_WAIT);
				tcp_set_timewait_timer(tsk);
			}
			else if(cb->flags & TCP_ACK){
				log(DEBUG,"收到ACK报文,进入TCP_FIN_WAIT_2状态");
				tcp_set_state(tsk, TCP_FIN_WAIT_2);
			}
			else if (cb->flags & TCP_FIN){
				log(DEBUG,"收到FIN报文,进入TCP_CLOSING状态"); 
				tcp_send_control_packet(tsk, TCP_ACK);
				tcp_set_state(tsk, TCP_CLOSING);
			}	
			break;
		}

		case TCP_FIN_WAIT_2:{
			if(cb->flags & TCP_FIN){
				log(DEBUG,"收到ACK报文,准备第四次挥手");
				tcp_set_state(tsk, TCP_TIME_WAIT);
				tcp_send_control_packet(tsk, TCP_ACK);
				tcp_set_timewait_timer(tsk);
			}
			break;
		}

		case TCP_CLOSING:{
			if(cb->flags & TCP_ACK){
				log(DEBUG,"收到ACK报文,进入TCP_TIME_WAIT状态");
				tcp_set_state(tsk, TCP_TIME_WAIT);
				tcp_set_timewait_timer(tsk);
			}
			break;
		}

		case TCP_LAST_ACK:{
			if(cb->flags & TCP_ACK){
				log(DEBUG,"收到ACK报文,连接关闭");
				tcp_set_state(tsk, TCP_CLOSED);
				tcp_unhash(tsk);
			}
			else{
				log(DEBUG,"收到非ACK报文,绝望的等待desuwa");
			}
			break;
		}
	}
}
