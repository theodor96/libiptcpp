#include <iostream>
#include <cstring>
#include <sys/errno.h>

#include <cstdlib>
#include <cstdio>
#include "libiptcpp.h"

#include <unistd.h>
#include <fcntl.h>

#include <linux/netfilter/xt_mark.h>


bool xtables_compatible_revision(const char *name, uint8_t revision)
{
	struct xt_get_revision rev;
	socklen_t s = sizeof(rev);
	int max_rev, sockfd;

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd < 0) {
		if (errno == EPERM) {
			/* revision 0 is always supported. */
			if (revision != 0)
				fprintf(stderr, "%s: Could not determine whether "
						"revision %u is supported, "
						"assuming it is.\n",
					name, revision);
			return true;
		}
		fprintf(stderr, "Could not open socket to kernel: %s\n",
			strerror(errno));
		return false;
	}

	if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) == -1) {
		fprintf(stderr, "Could not set close on exec: %s\n",
			strerror(errno));
		return false;
	}
	
	strcpy(rev.name, name);
	rev.revision = revision;

	max_rev = getsockopt(sockfd, IPPROTO_IP, IPT_SO_GET_REVISION_TARGET, &rev, &s);
	if (max_rev < 0) {
		/* Definitely don't support this? */
		if (errno == ENOENT || errno == EPROTONOSUPPORT) {
			close(sockfd);
			return false;
		} else if (errno == ENOPROTOOPT) {
			close(sockfd);
			/* Assume only revision 0 support (old kernel) */
			return (revision == 0);
		} else {
			fprintf(stderr, "getsockopt failed strangely: %s\n",
				strerror(errno));
			return false;
		}
	}
	close(sockfd);
	return true;
}

Rule::Rule() : mHandle(iptc_init("nat")), mRule()
{
	if (mHandle == NULL)
	{
		std::cout << "Error at initialization: " << iptc_strerror(errno) << "\n";
	}
}

void Rule::addMatchToRule()
{
	std::size_t thisMatchSize = XT_ALIGN(sizeof(ipt_entry_match)) +  XT_ALIGN(sizeof(xt_tcp));
	ipt_entry* newRule = reinterpret_cast<ipt_entry*>(new unsigned char[mRule->next_offset + thisMatchSize]);

	std::memset(newRule, 0, mRule->next_offset + thisMatchSize); // initialize everything to 0
	std::memcpy(newRule, mRule, mRule->target_offset); // copy everything from old rule until end of matches

	// update the match and total sizes to include our new match
	newRule->target_offset += thisMatchSize;
	newRule->next_offset += thisMatchSize;

	// set the protocol accordingly to the new match we want to add
	newRule->ip.proto = 6;

	ipt_entry_match* thisMatch = reinterpret_cast<ipt_entry_match*>(newRule->elems + mRule->target_offset - XT_ALIGN(sizeof(ipt_entry))); // add our new match right after all previous matches copied from old rule
	thisMatch->u.match_size = thisMatchSize;
	std::strcpy(thisMatch->u.user.name, "tcp");
	xt_tcp* thisMatchSpecific = reinterpret_cast<xt_tcp*>(thisMatch->data);
	thisMatchSpecific->spts[1] = 0xFFFF;
	thisMatchSpecific->dpts[0] = 80;
	thisMatchSpecific->dpts[1] = 80;

	std::memcpy(newRule->elems + thisMatchSize,
		         mRule->elems + mRule->target_offset - XT_ALIGN(sizeof(ipt_entry)),
		         mRule->next_offset - mRule->target_offset); // now copy everything else remaining from the old rule (basically the target)
	
	delete[] mRule;	         
	mRule = newRule;
}



void Rule::addMasqueradeRule()
{
	std::size_t matchLength = XT_ALIGN(sizeof(ipt_entry));
	
	std::cout << "sizeof ipt_entry = " << sizeof(ipt_ip) << " and XT_ALIGN(sizeof ipt entry) = " << XT_ALIGN(sizeof(ipt_ip)) << "\n\n\n";
	
	//std::size_t targetLength = XT_ALIGN(sizeof(xt_entry_target)) + XT_ALIGN(sizeof(nf_nat_ipv4_multi_range_compat));
	std::size_t targetLength = XT_ALIGN(sizeof(xt_entry_target)) + XT_ALIGN(sizeof(xt_mark_tginfo2));
	mRule = reinterpret_cast<ipt_entry*>(new unsigned char[matchLength + targetLength]);

	std::memset(mRule, 0, matchLength + targetLength);
	xt_entry_target* target = reinterpret_cast<xt_entry_target*>(mRule->elems);
	//nf_nat_ipv4_multi_range_compat* masquerade = reinterpret_cast<nf_nat_ipv4_multi_range_compat*>(target->data);
	xt_mark_tginfo2* mark = reinterpret_cast<xt_mark_tginfo2*>(target->data);

	mRule->target_offset = matchLength;
	mRule->next_offset = matchLength + targetLength;
	std::strcpy(mRule->ip.outiface, "qt0");

	target->u.target_size = targetLength;
	//std::strcpy(target->u.user.name, "MASQUERADE");
	//masquerade->rangesize = 1;
	
   std::strcpy(target->u.user.name, "MARK");
	mark->mark = 15;
	mark->mask = 0xFFFFFFFF;
	
	
	for (; target->u.user.revision < 10; ++target->u.user.revision)
	{
		if (!xtables_compatible_revision("MARK", target->u.user.revision))
		{
			std::cout << "MARK does not work with revision = " << static_cast<int>(target->u.user.revision) << "\n";
		}
		else
		{
			std::cout << "MARK WORKED with revision = " << static_cast<int>(target->u.user.revision) << "\n";
			break;
		}
	}

	addMatchToRule(); // alter the <already existing> rule by adding a match within it

	if (!iptc_append_entry("POSTROUTING", mRule, mHandle))
	{
		std::cout << "Failure to append MASQUERADE rule: " << iptc_strerror(errno) << "\n";
	}
	else
	{
		if (!iptc_commit(mHandle))
		{
			std::cout << "Failure to commit the changes: " << iptc_strerror(errno) << "\n";
		}
		else
		{
			std::cout << "Successfully commited all changes\n";
		}
	}

	delete[] mRule;
	iptc_free(mHandle);
}

