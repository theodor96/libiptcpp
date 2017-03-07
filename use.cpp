#include "libiptcpp.h"

int main()
{
   Rule* rule = new Rule();
   rule->addMasqueradeRule();
   return 0;
}

