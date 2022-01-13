# IPSec-bruteforce-prevention
This script parses log messages to find failed IPSec connections and bans IP addresses of brutforcers.

Script parses log entries every 5 minutes to find bruteforcers, then it creates address list `ipsec-brutforce-from-script` records.
In order to drop these addresses you need to create firewall rule in `filter` or `raw` chain.
E. g.: `/ip firewall raw
add action=drop chain=prerouting src-address-list=ipsec-brutforce-from-script`

**How to...**
1. Download [IPSec-bruteforce-prevention.rsc](https://raw.githubusercontent.com/mikrotik-user/IPSec-bruteforce-prevention/main/IPSec-bruteforce-prevention.rsc) on your mikrotik router `/tool fetch url="https://raw.githubusercontent.com/mikrotik-user/IPSec-bruteforce-prevention/main/IPSec-bruteforce-prevention.rsc" mode=https dst-path=IPSec-bruteforce-prevention.rsc`.
2. Import script `/import IPSec-bruteforce-prevention.rsc`.
3. Adjust scheduler permissions if required.
