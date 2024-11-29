// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * livepatch-skb-lookup-fix.c - Livepatch overriding *_lookup_skb
 *
 * Copyright (C) 2024 Oskar Stenman <oskar@cetex.se>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/printk.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/livepatch.h>
#include <net/inet_hashtables.h>
#include <linux/inetdevice.h>
#include <linux/filter.h>
#include <linux/version.h> 


/*
 * This livepatch fixes socket-lookups for packets transiting through a VRF
 * (packet arrived in VRF then routed to interface outside of VRF).
 *
 * It does so by adding fallback-lookups if no matching socket has been found
 * to the following two functions responsible for matching packets to new and 
 * existing connections.
 *
 * *** Packets for new TCP-connection-requests ***
 * net/ipv4/inet_hashtables.c:
 *   compute_score()
 *
 * *** Packets for existing TCP-connections ***
 * include/net/inet_hashtables.h: 
 *   inet_match()
 * 
 * To (easily) replace a function using livepatch the kernel needs to export 
 * the symbol of the function we're replacing - but the symbols of the modified
 * functions aren't exported so to replace them we have to replace their parents
 * (where the symbols are exported) including all intermediates / siblings.
 *
 * *** Packets for new TCP-connecction-requests ***
 * __inet_lookup_listener()
 *   -> inet_lhash2_lookup()
 *       -> compute_score()
 *
 * *** Packets for existing TCP-connections ***
 * __inet_lookup_established()
 *   inet_match()
 *
 * I chose to livepatch these functions since they are very simple and 
 * (I hope) the fix shouldn't break anything for newer or older 
 * kernel-releases even if applied to kernels where the core-issue
 * has been fixed.
 *
 * For more details see the git-repo and kernel-patch at:
 * https://github.com/cetex/linux-skb-lookup-fix
 *
 * The patch is automatically enabled upon loading the module.
 *
 * Example usage:
 *
 * $ make
 * $ insmod livepatch-skb-lookup-fix.o
 *
 * The patch is active and can be disabled temporarily by:
 * $ echo 0 > /ssy/kernel/livepatch/livepatch-skb-lookup-fix/enabled
 *
 * Unloading the module also disables it:
 * $ rmmod livepatch-skb-lookup-fix
 *
 */


/*
 * IPv4 TCP
 */

static inline bool inet_match__sklookupfix(struct net *net, const struct sock *sk,
                              const __addrpair cookie, const __portpair ports, 
			      int dif, int sdif)
{
        if (!net_eq(sock_net(sk), net) ||
            sk->sk_portpair != ports ||
            sk->sk_addrpair != cookie)
                return false;

        if (!inet_sk_bound_dev_eq(net, READ_ONCE(sk->sk_bound_dev_if), dif, sdif)) {
		// src-if not vrf or is bound to socket.
		if (sdif == 0 || sk->sk_bound_dev_if)
			return false;

		// We only get destination ifindex 'dif' here which can be the 
		// VRF-interface even though it's meant for loopback in the main 
		// routing-table - it should be accepted in that case.
		// So we have to check if daddr is assigned to the interface,
		// if not then it's probably meant for main loopback.
		//
		// Should maybe be fixed in whichever code sets dif so it points
		// to the real loopback.
		// This function would be much simpler if we just got the skb as
		// parameter. 

                rcu_read_lock();
		struct net_device *dst_dev = dev_get_by_index_rcu(net, dif);
		rcu_read_unlock();

		if (dst_dev && netif_is_l3_master(dst_dev)) {
			struct in_device *in_dev = __in_dev_get_rcu(dst_dev);

			if (!in_dev)
				return false;

			struct in_ifaddr *ifa;
			//__be32 daddr = (__be32)(cookie & 0xFFFFFFFF);
			__be32 daddr = (__be32)(cookie >> 32);
			printk("inet_match daddr=%pI4\n", &daddr);

			bool daddr_assigned_to_vrf = false;

			for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next) {
				if (ifa->ifa_address == daddr) {
					daddr_assigned_to_vrf = true;
					break;
				}
			}

			if (daddr_assigned_to_vrf)
				return false;
		}
	}
	return true;
}


struct sock *__inet_lookup_established__sklookupfix(struct net *net,
                                  struct inet_hashinfo *hashinfo,
                                  const __be32 saddr, const __be16 sport,
                                  const __be32 daddr, const u16 hnum,
                                  const int dif, const int sdif)
{
        INET_ADDR_COOKIE(acookie, saddr, daddr);
        const __portpair ports = INET_COMBINED_PORTS(sport, hnum);
        struct sock *sk;
        const struct hlist_nulls_node *node;
        /* Optimize here for direct hit, only listening connections can
         * have wildcards anyways.
         */
        unsigned int hash = inet_ehashfn(net, daddr, hnum, saddr, sport);
        unsigned int slot = hash & hashinfo->ehash_mask;
        struct inet_ehash_bucket *head = &hashinfo->ehash[slot];

begin:
        sk_nulls_for_each_rcu(sk, node, &head->chain) {
                if (sk->sk_hash != hash)
                        continue;
                if (likely(inet_match__sklookupfix(net, sk, acookie, ports, dif, sdif))) {
                        if (unlikely(!refcount_inc_not_zero(&sk->sk_refcnt)))
                                goto out;
                        if (unlikely(!inet_match__sklookupfix(net, sk, acookie,
                                                 ports, dif, sdif))) {
                                sock_gen_put(sk);
                                goto begin;
                        }
                        goto found;
                }
        }
        /*
         * if the nulls value we got at the end of this lookup is
         * not the expected one, we must restart lookup.
         * We probably met an item that was moved to another chain.
         */
        if (get_nulls_value(node) != slot)
                goto begin;
out:
        sk = NULL;
found:
        return sk;
}

static inline int compute_score__sklookupfix(struct sock *sk, const struct net *net,
                                struct sk_buff *skb, const unsigned short hnum,
                                const __be32 daddr, const int dif, const int sdif)
{
        int score = -1;
        printk("compute_score: dif=%d, sdif=%d\n", dif, sdif);


        if (net_eq(sock_net(sk), net) && sk->sk_num == hnum &&
                        !ipv6_only_sock(sk)) {
                if (sk->sk_rcv_saddr != daddr)
                        return -1;

                if (!inet_sk_bound_dev_eq(net, sk->sk_bound_dev_if, dif, sdif)) {
                        printk("compute_score: !inet_sk_bound_dev_eq() returned false\n");
			// src-if not vrf or is bound to socket.
			if (sdif == 0 || sk->sk_bound_dev_if)
				return -1;

                        struct net_device *dst_dev = skb_dst(skb)->dev;

		        printk("compute_score: dif=%d, sdif=%d dst_dev->name=%s, netif_is_l3_slave(dst_dev)=%d, netif_is_l3_master(dst_dev)=%d, sk->sk_bound_dev_if=%d\n", dif, sdif, dst_dev->name, netif_is_l3_slave(dst_dev), netif_is_l3_master(dst_dev), sk->sk_bound_dev_if);


			if (!dst_dev || netif_is_l3_slave(dst_dev) || netif_is_l3_master(dst_dev))
				return -1;

                }

                score =  sk->sk_bound_dev_if ? 2 : 1;

                if (sk->sk_family == PF_INET)
                        score++;
                if (READ_ONCE(sk->sk_incoming_cpu) == raw_smp_processor_id())
                        score++;
		printk("compute_score: score is: %d\n", score);
        }
        return score;
}

/* called with rcu_read_lock() : No refcount taken on the socket */
static struct sock *inet_lhash2_lookup__sklookupfix(const struct net *net,
                                struct inet_listen_hashbucket *ilb2,
                                struct sk_buff *skb, int doff,
                                const __be32 saddr, __be16 sport,
                                const __be32 daddr, const unsigned short hnum,
                                const int dif, const int sdif)
{
        struct sock *sk, *result = NULL;
        struct hlist_nulls_node *node;
        int score, hiscore = 0;

        sk_nulls_for_each_rcu(sk, node, &ilb2->nulls_head) {
                score = compute_score__sklookupfix(sk, net, skb, hnum, daddr, dif, sdif);
                if (score > hiscore) {
                        result = inet_lookup_reuseport(net, sk, skb, doff,
                                                       saddr, sport, daddr, hnum, inet_ehashfn);
                        if (result)
                                return result;

                        result = sk;
                        hiscore = score;
                }
        }

        return result;
}

struct sock *inet_lookup_run_sk_lookup__sklookupfix(const struct net *net,
                                       int protocol,
                                       struct sk_buff *skb, int doff,
                                       __be32 saddr, __be16 sport,
                                       __be32 daddr, u16 hnum, const int dif,
                                       inet_ehashfn_t *ehashfn)
{
        struct sock *sk, *reuse_sk;
        bool no_reuseport;

        no_reuseport = bpf_sk_lookup_run_v4(net, protocol, saddr, sport,
                                            daddr, hnum, dif, &sk);
        if (no_reuseport || IS_ERR_OR_NULL(sk))
                return sk;

        reuse_sk = inet_lookup_reuseport(net, sk, skb, doff, saddr, sport, daddr, hnum,
                                         ehashfn);
        if (reuse_sk)
                sk = reuse_sk;
        return sk;
}

struct sock *__inet_lookup_listener__sklookupfix(const struct net *net,
                                    struct inet_hashinfo *hashinfo,
                                    struct sk_buff *skb, int doff,
                                    const __be32 saddr, __be16 sport,
                                    const __be32 daddr, const unsigned short hnum,
                                    const int dif, const int sdif)
{
        struct inet_listen_hashbucket *ilb2;
        struct sock *result = NULL;
        unsigned int hash2;

        /* Lookup redirect from BPF */
        if (static_branch_unlikely(&bpf_sk_lookup_enabled) &&
            hashinfo == net->ipv4.tcp_death_row.hashinfo) {
                result = inet_lookup_run_sk_lookup__sklookupfix(net, IPPROTO_TCP, skb, doff,
                                                   saddr, sport, daddr, hnum, dif,
                                                   inet_ehashfn);
                if (result)
                        goto done;
        }

        hash2 = ipv4_portaddr_hash(net, daddr, hnum);
        ilb2 = inet_lhash2_bucket(hashinfo, hash2);

        result = inet_lhash2_lookup__sklookupfix(net, ilb2, skb, doff,
                                    saddr, sport, daddr, hnum,
                                    dif, sdif);
        if (result)
                goto done;

        /* Lookup lhash2 with INADDR_ANY */
        hash2 = ipv4_portaddr_hash(net, htonl(INADDR_ANY), hnum);
        ilb2 = inet_lhash2_bucket(hashinfo, hash2);

        result = inet_lhash2_lookup__sklookupfix(net, ilb2, skb, doff,
                                    saddr, sport, htonl(INADDR_ANY), hnum,
                                    dif, sdif);
done:
        if (IS_ERR(result))
                return NULL;
        return result;
}




/*
 * Livepatch stuff, kernel module initialization etc below.
 *
 * For more information about livepatch see:
 * https://www.kernel.org/doc/html/v6.12/livepatch/livepatch.html
 */

/* 
 * Define the livepatch functions array 
 *
 * https://www.kernel.org/doc/html/v6.12/livepatch/api.html#c.klp_func
 */
static struct klp_func funcs[] = {
        {
                .old_name = "__inet_lookup_listener",
                .new_func = __inet_lookup_listener__sklookupfix,
	},
	{
		.old_name = "__inet_lookup_established",
		.new_func = __inet_lookup_established__sklookupfix
        }, { }
};

/* 
 * Define the livepatch object
 *
 * https://www.kernel.org/doc/html/v6.12/livepatch/api.html#c.klp_object
 */
static struct klp_object objs[] = {
	{
		/* name being NULL means vmlinux */
		.funcs = funcs,
	}, { }
};

/* 
 * Define the livepatch patch
 *
 * https://www.kernel.org/doc/html/v6.12/livepatch/api.html#c.klp_patch
 */
static struct klp_patch patch = {
	.mod = THIS_MODULE,
	.objs = objs,
};


/* Initialize the livepatch module */
static int __init livepatch_init(void)
{
        pr_info("Loading livepatch module\n");
	return klp_enable_patch(&patch);
}

/* Exit the livepatch module */
static void __exit livepatch_exit(void)
{
    pr_info("Unloading livepatch module\n");
}

module_init(livepatch_init);
module_exit(livepatch_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Oskar Stenman <oskar@cetex.se>");
MODULE_INFO(livepatch, "Y");
MODULE_INFO(url, "https://github.com/cetex/linux-skb-lookup-fix");
MODULE_DESCRIPTION("Livepatch fixing the socket-lookup context for packets routed between VRFs");
