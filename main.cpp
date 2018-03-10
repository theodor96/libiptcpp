#include <iostream>
#include <map>
#include <vector>
#include <sstream>

#include <cstring>
#include <climits>
#include <cerrno>
#include <cstdlib>

#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if.h>

#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/x_tables.h>



// GCC pragmas for ip_tables.h header inclusion (implicit cast forbidden in C++)
// unfortunately with GCC > 6 it doesn't work because it complains that -fpermissive is not a warning
// see if can be worked around
/*

#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ > 2) || (__GNUC__ == 4 && __GNUC_MINOR__ == 2 && __GNUC_PATCHLEVEL__ > 3)
	#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ > 6) || (__GNUC__ == 4 && __GNUC_MINOR__ == 6 && __GNUC_PATCHLEVEL__ > 3)
		 #pragma GCC diagnostic push
	#endif

	#pragma GCC diagnostic ignored "-fpermissive"

	#include <linux/netfilter_ipv4/ip_tables.h>

	#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ > 6) || (__GNUC__ == 4 && __GNUC_MINOR__ == 6 && __GNUC_PATCHLEVEL__ > 3)
		 #pragma GCC diagnostic pop
	#endif
#else
	#error at least GCC 4.2.4 is required
#endif
*/





struct ipt_ip
{
	/* Source and destination IP addr */
	struct in_addr src, dst;
	/* Mask for src and dest IP addr */
	struct in_addr smsk, dmsk;
	char iniface[IFNAMSIZ], outiface[IFNAMSIZ];
	unsigned char iniface_mask[IFNAMSIZ], outiface_mask[IFNAMSIZ];

	/* Protocol, 0 = ANY */
	u_int16_t proto;

	/* Flags word */
	u_int8_t flags;
	/* Inverse flags */
	u_int8_t invflags;
};

/* Values for "flag" field in struct ipt_ip (general ip structure). */
#define IPT_F_FRAG		0x01	/* Set if rule is a fragment rule */
#define IPT_F_GOTO		0x02	/* Set if jump is a goto */
#define IPT_F_MASK		0x03	/* All possible flag bits mask. */

/* Values for "inv" field in struct ipt_ip. */
#define IPT_INV_VIA_IN		0x01	/* Invert the sense of IN IFACE. */
#define IPT_INV_VIA_OUT		0x02	/* Invert the sense of OUT IFACE */
#define IPT_INV_TOS		    0x04	/* Invert the sense of TOS. */
#define IPT_INV_SRCIP		0x08	/* Invert the sense of SRC IP. */
#define IPT_INV_DSTIP		0x10	/* Invert the sense of DST OP. */
#define IPT_INV_FRAG		0x20	/* Invert the sense of FRAG. */
#define IPT_INV_PROTO		XT_INV_PROTO
#define IPT_INV_MASK		0x7F	/* All possible flag bits mask. */

/* This structure defines each of the firewall rules.  Consists of 3
   parts which are 1) general IP header stuff 2) match specific
   stuff 3) the target to perform if the rule matches */
struct ipt_entry
{
	struct ipt_ip ip;

	/* Mark with fields that we care about. */
	unsigned int nfcache;

	/* Size of ipt_entry + matches */
	u_int16_t target_offset;
	/* Size of ipt_entry + matches + target */
	u_int16_t next_offset;

	/* Back pointer */
	unsigned int comefrom;

	/* Packet and byte counters. */
	struct xt_counters counters;

	/* The matches (if any), then the target. */
	unsigned char elems[0];
};

/*
 * New IP firewall options for [gs]etsockopt at the RAW IP level.
 * Unlike BSD Linux inherits IP options so you don't have to use a raw
 * socket for this. Instead we check rights in the calls.
 *
 * ATTENTION: check linux/in.h before adding new number here.
 */
#define IPT_BASE_CTL		64

#define IPT_SO_SET_REPLACE	(IPT_BASE_CTL)
#define IPT_SO_SET_ADD_COUNTERS	(IPT_BASE_CTL + 1)
#define IPT_SO_SET_MAX		IPT_SO_SET_ADD_COUNTERS

#define IPT_SO_GET_INFO			(IPT_BASE_CTL)
#define IPT_SO_GET_ENTRIES		(IPT_BASE_CTL + 1)
#define IPT_SO_GET_REVISION_MATCH	(IPT_BASE_CTL + 2)
#define IPT_SO_GET_REVISION_TARGET	(IPT_BASE_CTL + 3)
#define IPT_SO_GET_MAX			IPT_SO_GET_REVISION_TARGET

/* ICMP matching stuff */
struct ipt_icmp
{
	u_int8_t type;				/* type to match */
	u_int8_t code[2];			/* range of code */
	u_int8_t invflags;			/* Inverse flags */
};

/* Values for "inv" field for struct ipt_icmp. */
#define IPT_ICMP_INV	0x01	/* Invert the sense of type/code test */

/* The argument to IPT_SO_GET_INFO */
struct ipt_getinfo
{
	/* Which table: caller fills this in. */
	char name[XT_TABLE_MAXNAMELEN];

	/* Kernel fills these in. */
	/* Which hook entry points are valid: bitmask */
	unsigned int valid_hooks;

	/* Hook entry points: one per netfilter hook. */
	unsigned int hook_entry[NF_INET_NUMHOOKS];

	/* Underflow points. */
	unsigned int underflow[NF_INET_NUMHOOKS];

	/* Number of entries */
	unsigned int num_entries;

	/* Size of entries. */
	unsigned int size;
};

/* The argument to IPT_SO_SET_REPLACE. */
struct ipt_replace
{
	/* Which table. */
	char name[XT_TABLE_MAXNAMELEN];

	/* Which hook entry points are valid: bitmask.  You can't
           change this. */
	unsigned int valid_hooks;

	/* Number of entries */
	unsigned int num_entries;

	/* Total size of new entries */
	unsigned int size;

	/* Hook entry points. */
	unsigned int hook_entry[NF_INET_NUMHOOKS];

	/* Underflow points. */
	unsigned int underflow[NF_INET_NUMHOOKS];

	/* Information about old entries: */
	/* Number of counters (must be equal to current number of entries). */
	unsigned int num_counters;
	/* The old entries' counters. */
	struct xt_counters *counters;

	/* The entries (hang off end: not really an array). */
	struct ipt_entry entries[0];
};

/* The argument to IPT_SO_GET_ENTRIES. */
struct ipt_get_entries
{
	/* Which table: user fills this in. */
	char name[XT_TABLE_MAXNAMELEN];

	/* User fills this in: total entry size. */
	unsigned int size;

	/* The entries. */
	struct ipt_entry entrytable[0];
};











// Type definitions

using Int8   = int8_t;
using Int16  = int16_t;
using Int32  = int32_t;
using Int64  = int64_t;
using UInt8  = uint8_t;
using UInt16 = uint16_t;
using UInt32 = uint32_t;
using UInt64 = uint64_t;

using Raw   = unsigned char*;
using Chain = UInt16;
using Node  = ipt_entry*;

using NodeList           = std::vector<Node>;
using ChainToNameMap     = std::unordered_map<Chain, std::string>
using NodeToOwnerMap     = std::unordered_map<Node, Chain>;
using OwnerToNodeListMap = std::unordered_map<Chain, NodeList>;


/* old type defs - todo: get comments

typedef std::map<uint8_t,     std::string>                         				 IndexToChainsMap; // map from index of nf hook --> to name of that chain
typedef std::map<ipt_entry*,  std::string>                         				 RulesToChainsStartMap; // map from a pointer to an entry --> to the name of the chain that begins where that entry is. so from that pointer onwards, all other entries belong to the same table unless they are found at another position in our map
typedef std::map<std::string, std::vector<std::pair<std::string, ipt_entry*> > > ChainsToRulesMap; // map from the name of a table --> to the vector of rules it contains

*/

int getVerdict(ipt_entry* entry)
{
	// reinterpret this memory block as a target and get the verdict from that
	return reinterpret_cast<xt_standard_target*>(reinterpret_cast<Raw>(entry) + entry->target_offset)->verdict;
}

std::string getName(ipt_entry* entry)
{
	if (0 == std::strcmp(reinterpret_cast<xt_entry_target*>(reinterpret_cast<Raw>(entry) + entry->target_offset)->u.user.name, ""))
	{
		return "STANDARD";
	}

	return reinterpret_cast<const char *>(reinterpret_cast<xt_entry_target*>(reinterpret_cast<Raw>(entry) + entry->target_offset)->data);
}

std::string getSrc(ipt_entry* entry)
{
	char buffer[INET_ADDRSTRLEN];
	return inet_ntop(AF_INET, &entry->ip.src, buffer, sizeof buffer);
}

std::string getDst(ipt_entry* entry)
{
	char buffer[INET_ADDRSTRLEN];
	return inet_ntop(AF_INET, &entry->ip.dst, buffer, sizeof buffer);
}

ChainsToRulesMap parseFromKernel(const std::string& table)
{
	int socketFd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	// first we need a raw socket opened for communication with the kernel
	if (socketFd < 0)
	{
		std::cout << "sock < 0: " << strerror(errno) << "\n";
		abort();
	}

	// some information about the table that we're going to get the rules of, first...
	ipt_getinfo info;
	socklen_t length = sizeof info;
	std::strcpy(info.name, table.c_str());

	if (getsockopt(socketFd, IPPROTO_IP, IPT_SO_GET_INFO, &info, &length) < 0)
	{
		close(socketFd);

		std::cout << "getsockopt(sock, IPPROTO_IP, IPT_SO_GET_INFO, &info, sizeof info) < 0: " << strerror(errno) << "\n";
		abort();
	}

	// size of the next information that we get via getsockopt = size of struct where that information resides + size of all entries (returned from the info call above)
	length = sizeof(ipt_get_entries) + info.size;
	ipt_get_entries* entries = reinterpret_cast<ipt_get_entries*>(std::malloc(length));

	std::strcpy(entries->name, table.c_str());
	entries->size = info.size;

	if (getsockopt(socketFd, IPPROTO_IP, IPT_SO_GET_ENTRIES, entries, &length) < 0)
	{
		free(entries);
		close(socketFd);

		std::cout << "getsockopt(sock, IPPROTO_IP, IPT_SO_GET_ENTRIES, &entries, &length) < 0: " << strerror(errno) << "\n";
		abort();
	}

	close(socketFd);

	// define our maps here (see typedefs) + fill the hardcoded map with index->name ----> see how to get that dynamically -> study kernel sources

	ChainsToRulesMap rules;
	IndexToChainsMap chains;
	RulesToChainsStartMap chainsStart;
	chains.insert({0, "PREROUTING"});
	chains.insert({1, "INPUT"});
	chains.insert({2, "FORWARD"});
	chains.insert({3, "OUTPUT"});
	chains.insert({4, "POSTROUTING"});

	for (int i = 0; i < chains.size(); ++i)
	{
		// in info.valid_hooks we have binary flags ORed with powers of 2^ (index of chain)
		// so here we verify if the table we're parsing right now has a certain chain (e.g. in NAT table we only have 3 chains, but FILTER has 5 chains, etc)
		if (info.valid_hooks & (1 << i))
		{
			// if chain i is valid for this table, then insert it in the map so we can build the vector of entries corresponding to chain i later
			rules.insert({chains[i], ChainsToRulesMap::value_type::second_type()});

			// in info.hook_entry we have the offsets from the beginning of the blob (entrytable) until the first rule from chain i
			// so we put in the map the corresponding pointer to the corresponding chain so that we can find it later so we know where each chain begins
			chainsStart.insert({reinterpret_cast<ipt_entry*>(reinterpret_cast<Raw>(entries->entrytable) + info.hook_entry[i]), chains[i]});
		}
	}

	// this is NULL in the beginning but is assigned in first line in for block, then i increments with entry->next_offset to go the next rule
	ipt_entry* entry = NULL;
	// this is a pointer to a vector of rules. this gets reassigned for each rule to the corresponding vector in the rules map so it goes like:
	// when the beginning of a new chain is detected, reassign pushInto pointer. from that point onwards, all entries will go there until we find another entry to be the beginning of another chain
	std::vector<std::pair<std::string, ipt_entry*> >* pushInto = NULL;

	for (int i = 0; i < entries->size; i += entry->next_offset)
	{

	    entry = reinterpret_cast<ipt_entry*>(reinterpret_cast<Raw>(entries->entrytable) + i);

	    // every nf table ends with an ERROR node
	    if (i + entry->next_offset == entries->size)
	    {
	    	// this is the last entry for this table - a dummy ERROR target that we don't want to take into consideration
	    	break;
	    }

		 // node with a target having name "ERROR" means the node is actually a user defined chain. this means 2 things: the name of the user defined chain
		 // is found in the "data" of the target as a const char* (maximum XT_FUNCTION_MAXNAMELEN chars)
		 // and the second thing from this point onwards, rules belong to this user defined chain
	    if (0 == std::strcmp(reinterpret_cast<xt_entry_target*>(reinterpret_cast<Raw>(entry) + entry->target_offset)->u.user.name, "ERROR"))
	    {
	    	std::pair<ChainsToRulesMap::iterator, bool> newChainItr = rules.insert({reinterpret_cast<const char*>(reinterpret_cast<xt_entry_target*>(reinterpret_cast<Raw>(entry) + entry->target_offset)->data),
						 	 	 	 	 	 	 	 	 	                       ChainsToRulesMap::value_type::second_type()});

	    	pushInto = &newChainItr.first->second;

	    	ipt_entry* next_entry = reinterpret_cast<ipt_entry*>(reinterpret_cast<Raw>(entry) + entry->next_offset);
	    	std::cout << "user chain = " << newChainItr.first->first << "; offset for this error node = " << reinterpret_cast<Raw>(entry) - reinterpret_cast<Raw>(entries->entrytable) << "; offset for first rule = " << reinterpret_cast<Raw>(next_entry) - reinterpret_cast<Raw>(entries->entrytable) << "\n";
	    }
	    else
	    {
		    // is this entry the beginning of a new chain? if so, reassign the pushInto pointer, otherwise keep the pointer where it was so we insert in the same vector for the same chain
		    RulesToChainsStartMap::const_iterator chainStartingWithItr = chainsStart.find(entry);
		    if (chainsStart.end() != chainStartingWithItr)
		    {
		    	//std::cout << "now adding shit in table `" << chainStartingWithItr->second << "`\n";
		    	pushInto = &rules[chainStartingWithItr->second];
		    }

		    // this should never happen, the very first rule we parse should be found as the beginning of a certain chain. if not, something is WRONG
		    if (pushInto == NULL)
		    {
		    	// TODO: assert here
		    	std::cout << "pushInto is NULL\n";
		    	abort();
		    }

		    std::string ruleName = "UNNAMED";
		    if (0 == strcmp(reinterpret_cast<xt_entry_target*>(reinterpret_cast<Raw>(entry) + entry->target_offset)->u.user.name, ""))
		    {
			    if (getVerdict(entry) < 0)
			    {
			    	switch (getVerdict(entry))
			    	{
						case (-NF_DROP - 1):
						{
							ruleName = "DROP";
							break;
						}

						case (-NF_ACCEPT - 1):
						{
							ruleName = "ACCEPT";
							break;
						}

						case (XT_RETURN):
						{
							ruleName = "RETURN";
							break;
						}
			    	}
			    }
			    else
				{
			    	if (getVerdict(entry) == XT_CONTINUE)
			    	{
			    		ruleName = "CONTINUE";
			    	}
			    	else
			    	{
				    	int currentRuleOffset = reinterpret_cast<Raw>(entry) - reinterpret_cast<Raw>(entries->entrytable);

				    	if (getVerdict(entry) == currentRuleOffset + entry->next_offset)
				    	{
				    		ruleName = "FALLTHROUGH";
				    	}
				    	else
				    	{
				    		// verdict tell us the offset of the first rule contained in the jump-to chain

				    		// so the first node BEFORE the rule described above must be the ERROR node

				    		// we know that ERROR nodes that indicate beginning of user-defined chain
				    		// consist of an xt_entry_target + maximum XT_FUNCTION_MAXNAMELEN characters representing the name of the chain

				    		// so here if we have the first rule offset, just subtract from it XT_FUNCTION_MAXNAMELEN and reinterpret it as const char* and that must be the name!
				    		ruleName = "JUMP to " + std::string(reinterpret_cast<const char*>(reinterpret_cast<Raw>(entries->entrytable) + getVerdict(entry) - XT_ALIGN(XT_FUNCTION_MAXNAMELEN)));
				    	}
			    	}
				}
		    }
		    else
		    {
		    	ruleName = reinterpret_cast<xt_entry_target*>(reinterpret_cast<Raw>(entry) + entry->target_offset)->u.user.name;
		    }

		    // push the rule in the corresponding vector for the corresponding chain
		    pushInto->push_back(std::make_pair(ruleName, entry));
	    }
	}

	free(entries);
	return rules;
}

int main()
{
	std::vector<const char*> tables;
	tables.push_back("filter");
	tables.push_back("mangle");
	tables.push_back("nat");
	tables.push_back("raw");

	parseFromKernel("nat");

	/*for (std::vector<const char*>::const_iterator tableItr = tables.begin(); tableItr != tables.end(); ++tableItr)
	{
		ChainsToRulesMap chainsToRules = parseFromKernel(*tableItr);

		if (chainsToRules.empty())
		{
			// TODO: assert here
			std::cout << "something went terribly wrong...\n";
			abort();
		}

		std::cout << "Table `" << *tableItr << "`:\n";

		for (ChainsToRulesMap::const_iterator itr = chainsToRules.begin(); itr != chainsToRules.end(); ++itr)
		{
			if (itr->second.empty())
			{
				// TODO: assert here
				std::cout << itr->first << " has no rules!!!!!!!!\n";
				continue;
			}

			std::cout << "    Chain `" << itr->first << "`\n";

			for (ChainsToRulesMap::mapped_type::const_iterator ruleItr = itr->second.begin(); ruleItr != itr->second.end(); ++ruleItr)
			{
				std::cout << "        Rule `" << ruleItr->first << "` with dst = `" << getSrc(ruleItr->second) << "` and dst = `" << getDst(ruleItr->second) << "`\n";
			}
		}
	}*/

	return 0;
}
