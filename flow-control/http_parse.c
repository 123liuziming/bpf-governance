#include <linux/ptrace.h>
#include <bcc/proto.h>
#include <uapi/linux/bpf_common.h>
#include <uapi/linux/bpf.h>

#define IP_TCP 	6
#define ETH_HLEN 14
#define MAX_STR_LEN 2048
#define MAX_PATH_LEN 256


#define METHOD_FLAG 0
#define PATH_FLAG 1

struct session_key {
	u32 src_ip;               //source ip
	u32 dst_ip;               //destination ip
	unsigned short src_port;  //source port
	unsigned short dst_port;  //destination port
};

struct header_key {
	struct session_key key;
	char* header;
};

struct path_key {
	struct session_key key;
	char* path;
};

struct method_value {
	char method[5];
};

struct long_str {
	char inner_str[MAX_STR_LEN];
	int index;
	int align;
};

struct path_rule {
	char path_str[MAX_PATH_LEN];
	int length;
	int qps;
};


// key is session, value is the http header string
BPF_ARRAY(path_rules, struct path_rule);
BPF_HASH(p_int2Str, u32, char);

BPF_HASH(method_map, struct session_key, struct method_value);
BPF_HASH(path_map, struct session_key, struct long_str);
BPF_HASH(session_str_map, struct session_key, struct long_str);
BPF_PERCPU_ARRAY(string_arr, struct long_str);

static inline int is_http(char p[]) {
	//HTTP
	if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
		return 9;
	}
	//GET
	if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T')) {
		return 4;
	}
	//POST
	if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T')) {
		return 5;
	}
	//PUT
	if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T')) {
		return 4;
	}
	//DELETE
	if ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E')) {
		return 7;
	}
	//HEAD
	if ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D')) {
		return 5;
	}
	return 0;
}

int http_filter(struct __sk_buff *skb) {

	u8 *cursor = 0;

	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	//filter IP packets (ethernet type = 0x0800)
	if (!(ethernet->type == 0x0800)) {
		goto DONE;
	}

	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
	//filter TCP packets (ip next protocol = 0x06)
	if (ip->nextp != IP_TCP) {
		goto DONE;
	}

	u32 tcp_header_length = 0;
	u32 ip_header_length = 0;
	u32 payload_offset = 0;
	u32 payload_length = 0;
	struct session_key session_key;

    //calculate ip header length
    //value to multiply * 4
    //e.g. ip->hlen = 5 ; IP Header Length = 5 x 4 byte = 20 byte
    ip_header_length = ip->hlen << 2;    //SHL 2 -> *4 multiply

    //check ip header length against minimum
    if (ip_header_length < sizeof(*ip)) {
        goto DONE;
    }

    //shift cursor forward for dynamic ip header size
    void *_ = cursor_advance(cursor, (ip_header_length-sizeof(*ip)));

	struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

	//retrieve ip src/dest and port src/dest of current packet
	//and save it into struct session_key
	session_key.dst_ip = ip->dst;
	session_key.src_ip = ip->src;
	session_key.dst_port = tcp->dst_port;
	session_key.src_port = tcp->src_port;

	//calculate tcp header length
	//value to multiply *4
	//e.g. tcp->offset = 5 ; TCP Header Length = 5 x 4 byte = 20 byte
	tcp_header_length = tcp->offset << 2; //SHL 2 -> *4 multiply

	//calculate payload offset and length
	payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
	payload_length = ip->tlen - ip_header_length - tcp_header_length;

	//http://stackoverflow.com/questions/25047905/http-request-minimum-size-in-bytes
	//minimum length of http request is always geater than 7 bytes
	//avoid invalid access memory
	//include empty payload
	if(payload_length < 7) {
		goto DONE;
	}

	struct long_str* session_str = session_str_map.lookup(&session_key);
	char p[8];
	int key1 = 0;
	int i = 0;
	int first = 0;
	bpf_skb_load_bytes(skb, payload_offset, p, 8);
	if (!session_str) {
		if (!(first = is_http(p))) {
			goto DONE;
		}
		session_str = string_arr.lookup(&key1);
		if (session_str) {
			session_str->index = 0;
		}
	}
	int length = MAX_STR_LEN;
	if (length > payload_length) {
		length = payload_length;
	}

	int bytes_read = 0;
	for (i = 0; i < 256; ++i) {
		bytes_read += 8;
		if (bytes_read > length) {
			break;
		}
		bpf_skb_load_bytes(skb, payload_offset, p, 8);
		payload_offset += 8;
		unsigned int index = session_str->index;
		index %= MAX_STR_LEN;
		if (session_str) {
			memcpy(session_str->inner_str + index, p, 8);
			session_str->index += 8;
			if (bytes_read > length) {
				break;
			}
		}
	}

	int t_idx = 0;
	struct path_rule* pat = path_rules.lookup(&key1);
	if (!pat) {
		return 0;
	}

	bpf_trace_printk("pat str is %s\n", pat->path_str);
	for (i = 0; i < 256; ++i) {
		bpf_probe_read_kernel(p, 1, session_str->inner_str + first + i);
		bpf_probe_read_kernel(p + 1, 1, pat->path_str + i);
		if (t_idx >= pat->length) {
			bpf_trace_printk("Match! %d %d %d\n", first, p[0], p[1]);
			break;
		}
		if (p[0] == p[1]) {
			t_idx++;
			continue;
		}
		t_idx = 0;
	}

	if (session_str) {
		session_str_map.update(&session_key, session_str);	
	}

	return 0;

	DROP:
	return 2;

	DONE:
	return 0;

}
