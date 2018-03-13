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
#include <unordered_map>
#include <linux/netfilter.h>
#include <linux/netfilter/xt_tcpudp.h>
#include <sstream>











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


template <std::size_t SizeT, std::size_t MaskT>
struct DoAlignment
{
private:
    static const std::size_t InvertedMask = ~MaskT;
    
public:
    static const std::size_t Value = (SizeT + MaskT) & InvertedMask;
};

template <typename TypeToAlignT, typename StandardT>
struct AlignToRequirementOfStandardType
{
    static const std::size_t Value = DoAlignment<sizeof(TypeToAlignT), __alignof(StandardT) - 1>::Value;
};

template <typename T>
struct AlignToNetfilter
{
    static const std::size_t Value = AlignToRequirementOfStandardType<T, ipt_entry>::Value;   
};



namespace std
{
	template <>
	struct hash<nf_inet_hooks>
	{
		std::size_t operator()(const nf_inet_hooks& iValue) const
		{
			return hash<int>()(static_cast<int>(iValue));
		}
	};
}
































enum TargetType
{
	E_STANDARD_TARGET,
	E_ERROR_TARGET,
	E_CUSTOM_TARGET
};

TargetType getTargetType(xt_entry_target* target)
{
	if (0 == strcmp(target->u.user.name, ""))
	{
		return E_STANDARD_TARGET;
	}
	else if (0 == strcmp(target->u.user.name, "ERROR"))
	{
		return E_ERROR_TARGET;
	}
	else
	{
		return E_CUSTOM_TARGET;
	}
}

std::string getVerdict(int verdict)
{
	if (verdict < 0)
	{
		switch (verdict)
		{
			case -NF_REPEAT - 1:
				return "RETURN";
			case -NF_ACCEPT-1:
				return "ACCEPT";
			case -NF_DROP-1:
				return "DROP";
			case -NF_QUEUE-1:
				return "QUEUE";
			default:
				std::cout << "UNKNOWN VERDICT\n\n\n";
				abort();
				break;
		}
	}
	else
	{
		std::ostringstream x;
		x << verdict;
		return "JUMP to [" + x.str() + "]";
	}
}

void parseFromKernel(const std::string& iTable)
{
	int socketFd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (socketFd < 0)
	{
		std::cout << "sock < 0: " << strerror(errno) << "\n";
		abort();
	}
	




	ipt_getinfo info;
	socklen_t length = sizeof info;
	std::strcpy(info.name, iTable.c_str());
	if (getsockopt(socketFd, IPPROTO_IP, IPT_SO_GET_INFO, &info, &length) < 0)
	{
		close(socketFd);

		std::cout << "getsockopt(sock, IPPROTO_IP, IPT_SO_GET_INFO, &info, sizeof info) < 0: " << strerror(errno) << "\n";
		abort();
	}
	
	
	
	
	
	
	std::unordered_map<nf_inet_hooks, std::string> chains{ {NF_INET_PRE_ROUTING, "PREROUTING"}, {NF_INET_LOCAL_IN, "INPUT"}, {NF_INET_FORWARD, "FORWARD"}, {NF_INET_LOCAL_OUT, "OUTPUT"}, {NF_INET_POST_ROUTING, "POSTROUTING"} }; 
	std::cout << "Table " << iTable << ":" << std::endl;
	for (std::unordered_map<nf_inet_hooks, std::string>::const_iterator itr = chains.begin(); itr != chains.end(); ++itr)
	{
		if (info.valid_hooks & (1 << itr->first))
		{
			std::cout << "chain " << itr->second << " begins at ["<< info.hook_entry[itr->first] << "], ends at [" << info.underflow[itr->first] << "]" << std::endl;
		}
	}
	std::cout << "info.size = " << info.size << std::endl;
	std::cout << "info.num_entries = " << info.num_entries << std::endl;
	std::cout << std::endl << std::endl;
	
	




	length = sizeof(ipt_get_entries) + info.size;
	ipt_get_entries* entries = reinterpret_cast<ipt_get_entries*>(std::malloc(length));
	std::strcpy(entries->name, iTable.c_str());
	entries->size = info.size;
	if (getsockopt(socketFd, IPPROTO_IP, IPT_SO_GET_ENTRIES, entries, &length) < 0)
	{
		free(entries);
		close(socketFd);

		std::cout << "getsockopt(sock, IPPROTO_IP, IPT_SO_GET_ENTRIES, &entries, &length) < 0: " << strerror(errno) << "\n";
		abort();
	}

	
	
	
	
	int itr = 0;
	ipt_entry* entry = NULL;
	for (int i = 0; i < entries->size; i += entry->next_offset)
	{
		 itr++;
	    entry = reinterpret_cast<ipt_entry*>(reinterpret_cast<unsigned char*>(entries->entrytable) + i);
		
		xt_entry_target* xxx = reinterpret_cast<xt_entry_target*>(reinterpret_cast<unsigned char*>(entry) + entry->target_offset);
		int* verdict = reinterpret_cast<int*>(xxx->data);
		char* name = reinterpret_cast<char*>(xxx->data);
	    
	    /*if (i + entry->next_offset == entries->size) 
	    {
	    	std::cout << "ERR entry " << itr << " has: target_offset = " << entry->target_offset << ", next_offset = "
			<< entry->next_offset
			<< ", target_size = " << xxx->u.user.target_size
			<< ", target_name = `" << xxx->u.user.name << "`" << std::endl;*/
	    //}
	    //else
	    {
	    	std::cout << "entry " << itr << " has: offset = " << i << ", target_offset = " << entry->target_offset << ", next_offset = "
			<< entry->next_offset
			<< ", target_size = " << xxx->u.user.target_size
			<< ", target_name = `" << xxx->u.user.name << "`"
			<< ", verdict = `" << *verdict << "`"
			<< ", name = `" << name << "`" << std::endl;
			
			TargetType type = getTargetType(xxx);
			if (E_STANDARD_TARGET == type)
			{
				xt_standard_target* stdTarget = reinterpret_cast<xt_standard_target*>(reinterpret_cast<unsigned char*>(entry) + entry->target_offset);
				std::cout << "entry " << itr << " is STANDARD with verdict = " << getVerdict(stdTarget->verdict) << "\n\n";
			}
			else if (E_ERROR_TARGET == type)
			{
				xt_error_target* errTarget = reinterpret_cast<xt_error_target*>(reinterpret_cast<unsigned char*>(entry) + entry->target_offset);
				std::cout << "entry " << itr << " is ERROR with name = " << errTarget->errorname << "\n\n";
			}
			else if (E_CUSTOM_TARGET == type)
			{
				std::cout << "entry " << itr << " is CUSTOM with name = " << xxx->u.user.name << "\n\n";
			}
	    }
	}
	free(entries);
}

int main(int argc, char** argv)
{
	parseFromKernel(argv[1]);

	return 0;
}
