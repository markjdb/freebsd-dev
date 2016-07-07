#ifndef _SDP_DBG_H_
#define _SDP_DBG_H_

#define SDPSTATS_ON

//#define GETNSTIMEODAY_SUPPORTED

#define _sdp_printk(func, line, level, sk, format, arg...)	\
do {								\
	printk(level "%s:%d %p sdp_sock(%d:%d %d:%d): " format "\n",	\
	       func, line, sk ? sdp_sk(sk) : NULL,		\
	       curproc->p_pid, PCPU_GET(cpuid),			\
	       (sk) && sdp_sk(sk) ? ntohs(sdp_sk(sk)->lport) : -1,	\
	       (sk) && sdp_sk(sk) ? ntohs(sdp_sk(sk)->fport) : -1, ## arg);	\
} while (0)
#define sdp_printk(level, sk, format, arg...)                \
	_sdp_printk(__func__, __LINE__, level, sk, format, ## arg)
#define sdp_warn(sk, format, arg...)                         \
	sdp_printk(KERN_WARNING, sk, format , ## arg)

#define SDP_MODPARAM_SINT(var, def_val, msg) \
	static int var = def_val; \
	module_param_named(var, var, int, 0644); \
	MODULE_PARM_DESC(var, msg " [" #def_val "]"); \

#define SDP_MODPARAM_INT(var, def_val, msg) \
	int var = def_val; \
	module_param_named(var, var, int, 0644); \
	MODULE_PARM_DESC(var, msg " [" #def_val "]"); \

#ifdef CONFIG_INFINIBAND_SDP_DEBUG
extern int sdp_debug_level;

#define sdp_dbg(sk, format, arg...)                          \
	do {                                                 \
		if (sdp_debug_level > 0)                     \
		sdp_printk(KERN_WARNING, sk, format , ## arg); \
	} while (0)

#else /* CONFIG_INFINIBAND_SDP_DEBUG */
#define sdp_dbg(priv, format, arg...)                        \
	do { (void) (priv); } while (0)
#define sock_ref(sk, msg, sock_op) sock_op(sk)
#endif /* CONFIG_INFINIBAND_SDP_DEBUG */

#ifdef CONFIG_INFINIBAND_SDP_DEBUG_DATA

extern int sdp_data_debug_level;
#define sdp_dbg_data(sk, format, arg...)                     		\
	do {                                                 		\
		if (sdp_data_debug_level & 0x2)                		\
			sdp_printk(KERN_WARNING, sk, format , ## arg); 	\
	} while (0)
#define SDP_DUMP_PACKET(sk, str, mb, h)                     		\
	do {                                                 		\
		if (sdp_data_debug_level & 0x1)                		\
			dump_packet(sk, str, mb, h); 			\
	} while (0)
#else
#define sdp_dbg_data(priv, format, arg...)
#define SDP_DUMP_PACKET(sk, str, mb, h)
#endif

#define ENUM2STR(e) [e] = #e

static inline char *sdp_state_str(int state)
{
	static char *state2str[] = {
		ENUM2STR(TCPS_ESTABLISHED),
		ENUM2STR(TCPS_SYN_SENT),
		ENUM2STR(TCPS_SYN_RECEIVED),
		ENUM2STR(TCPS_FIN_WAIT_1),
		ENUM2STR(TCPS_FIN_WAIT_2),
		ENUM2STR(TCPS_TIME_WAIT),
		ENUM2STR(TCPS_CLOSED),
		ENUM2STR(TCPS_CLOSE_WAIT),
		ENUM2STR(TCPS_LAST_ACK),
		ENUM2STR(TCPS_LISTEN),
		ENUM2STR(TCPS_CLOSING),
	};

	if (state < 0 || state >= ARRAY_SIZE(state2str))
		return "unknown";

	return state2str[state];
}

struct sdp_bsdh;
#ifdef CONFIG_INFINIBAND_SDP_DEBUG_DATA
void _dump_packet(const char *func, int line, struct socket *sk, char *str,
		struct mbuf *mb, const struct sdp_bsdh *h);
#define dump_packet(sk, str, mb, h) \
	_dump_packet(__func__, __LINE__, sk, str, mb, h)
#endif

#endif
