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
#include <linux/netfilter_ipv4/ip_tables.h>

typedef unsigned char* Raw;
typedef std::map<uint8_t,     std::string>                         				 IndexToChainsMap; // map from index of nf hook --> to name of that chain
typedef std::map<ipt_entry*,  std::string>                         				 RulesToChainsStartMap; // map from a pointer to an entry --> to the name of the chain that begins where that entry is. so from that pointer onwards, all other entries belong to the same table unless they are found at another position in our map
typedef std::map<std::string, std::vector<std::pair<std::string, ipt_entry*> > > ChainsToRulesMap; // map from the name of a table --> to the vector of rules it contains

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
	chains.insert(IndexToChainsMap::value_type(0, "PREROUTING"));
	chains.insert(IndexToChainsMap::value_type(1, "INPUT"));
	chains.insert(IndexToChainsMap::value_type(2, "FORWARD"));
	chains.insert(IndexToChainsMap::value_type(3, "OUTPUT"));
	chains.insert(IndexToChainsMap::value_type(4, "POSTROUTING"));

	for (int i = 0; i < chains.size(); ++i)
	{
		// in info.valid_hooks we have binary flags ORed with powers of 2^ (index of chain)
		// so here we verify if the table we're parsing right now has a certain chain (e.g. in NAT table we only have 3 chains, but FILTER has 5 chains, etc)
		if (info.valid_hooks & (1 << i))
		{
			// if chain i is valid for this table, then insert it in the map so we can build the vector of entries corresponding to chain i later
			rules.insert(ChainsToRulesMap::value_type(chains[i], ChainsToRulesMap::value_type::second_type()));

			// in info.hook_entry we have the offsets from the beginning of the blob (entrytable) until the first rule from chain i
			// so we put in the map the corresponding pointer to the corresponding chain so that we can find it later so we know where each chain begins
			chainsStart.insert(
					RulesToChainsStartMap::value_type(
							reinterpret_cast<ipt_entry*>(reinterpret_cast<Raw>(entries->entrytable) + info.hook_entry[i]),
							chains[i]));
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



	    if (0 == std::strcmp(reinterpret_cast<xt_entry_target*>(reinterpret_cast<Raw>(entry) + entry->target_offset)->u.user.name, "ERROR"))
	    {
	    	std::pair<ChainsToRulesMap::iterator, bool> newChainItr = rules.insert(ChainsToRulesMap::value_type(reinterpret_cast<const char *>(reinterpret_cast<xt_entry_target*>(reinterpret_cast<Raw>(entry) + entry->target_offset)->data),
						 	 	 	 	 	 	 	 	 	                             ChainsToRulesMap::value_type::second_type()));

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

	for (std::vector<const char*>::const_iterator tableItr = tables.begin(); tableItr != tables.end(); ++tableItr)
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
	}
	
	return 0;
}
