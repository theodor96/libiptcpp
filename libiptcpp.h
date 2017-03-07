#include <libiptc/libiptc.h>

struct xt_mark_tginfo2 {
         __u32 mark, mask;
 };
         
union nf_conntrack_man_proto
{
	__be16 all;
	
	struct
	{
		__be16 port;
	} tcp;
   
   struct
   {
   	__be16 port;
   } udp;
   
   struct
   {
       __be16 id;
   } icmp;
   
   struct
   {
       __be16 port;
   } dccp;
   
   struct
   {
       __be16 port;
   } sctp;
   
   struct
   {
       __be16 key;
   } gre;
};
  
struct nf_nat_ipv4_range
{
    unsigned int           flags;
    __be32                 min_ip;
    __be32                 max_ip;
    nf_conntrack_man_proto min;
    nf_conntrack_man_proto max;
};

struct nf_nat_ipv4_multi_range_compat
{
    unsigned int      rangesize;
    nf_nat_ipv4_range range[1];
};

class Rule
{
public:
	Rule();
	
	void addMatchToRule();
	
	void addMasqueradeRule();
	
private:
	iptc_handle* mHandle;
	ipt_entry* mRule;
};

