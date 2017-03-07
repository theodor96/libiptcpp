#include <iostream>
#include <cstring>
#include <sys/errno.h>

#include "libiptcpp.h"

Rule::Rule() : mHandle(iptc_init("nat")), mRule()
{
	if (mHandle == NULL)
	{
		std::cout << "Error at initialization: " << iptc_strerror(errno) << "\n";
	}
}

class Match
{
public:
	Match() : mSize(0), mData()
	{
	
	}
	
	int getSize() const { return mSize; }
	
	ipt_entry_match* getRaw() const { return mData; }
	
private:
	
	int mSize;
	ipt_entry_match* mData;
}

void Rule::addMatch(const Match* match)
{
	ipt_entry* newRule = reinterpret_cast<ipt_entry*>(new unsigned char[mRule->next_offset + match->getSize()]);
	
	std::fill(newRule, newRule + mRule->next_offset + match->getSize(), 0); // initialize everything to 0
	std::copy(mRule, mRule + mRule->target_offset, newRule); // copy everything from old rule until end of matches

	// update the match and total sizes to include our new match
	newRule->target_offset += match->getSize();
	newRule->next_offset += match->getSize();
	
	std::copy(match->getRaw(),
	          match->getRaw() + match->getSize(),
	          newRule->elems + mRule->target_offset - XT_ALIGN(sizeof(ipt_entry))); // add our new match right after all previous matches copied from old rule
	
	std::copy(mRule->elems + mRule->target_offset - XT_ALIGN(sizeof(ipt_entry),
	          mRule->elems + mRule->next_offset - mRule->target_offset,
	          newRule->elems + match->getSize()); // now copy everything else remaining from the old rule (basically the target)
	
	delete[] mRule;	         
	mRule = newRule;
}

void Rule::addMasqueradeRule()
{
	std::size_t matchLength = XT_ALIGN(sizeof(ipt_entry));
	std::size_t targetLength = XT_ALIGN(sizeof(xt_entry_target)) + XT_ALIGN(sizeof(nf_nat_ipv4_multi_range_compat));
	mRule = reinterpret_cast<ipt_entry*>(new unsigned char[matchLength + targetLength]);

	std::memset(mRule, 0, matchLength + targetLength);
	xt_entry_target* target = reinterpret_cast<xt_entry_target*>(mRule->elems);
	nf_nat_ipv4_multi_range_compat* masquerade = reinterpret_cast<nf_nat_ipv4_multi_range_compat*>(target->data);

	mRule->target_offset = matchLength;
	mRule->next_offset = matchLength + targetLength;
	std::strcpy(mRule->ip.outiface, "qtIntf0");

	target->u.target_size = targetLength;
	std::strcpy(target->u.user.name, "MASQUERADE");
	masquerade->rangesize = 1;

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

