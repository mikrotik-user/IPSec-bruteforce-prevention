# IPSec-bruteforce-prevention
This script parses log messages to find failed IPSec connections and bans IP addresses of brutforcers.

This script parses log entries every 5 minutes to find bruteforcers, then it creates address list `ipsec-brutforce-from-script` records.
In order to drop these addresses you need to create firewall rule in `filter` or `raw` chain.
E. g.:
`/ip firewall raw
add action=drop chain=prerouting src-address-list=ipsec-brutforce-from-script`

**How to...**
