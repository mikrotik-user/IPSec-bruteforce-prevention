/system scheduler
add interval=5m name=IPSec-bruteforce-prevention on-event="# This script compi\
    led from various sources found on Internet\r\
    \n\r\
    \n# How many failed attempts from the same IP address will trigger script \
    to ban this IP address\r\
    \n:local pop 1\r\
    \n# IP address found in log\r\
    \n:local ipaddr\r\
    \n# Messages array\r\
    \n:local ipsec\r\
    \n\r\
    \n# Searching for \"failed to get valid proposal\" string in log.\r\
    \n:set ipsec [/log find message~\"failed to get valid proposal\" time>([/s\
    ystem clock get time] - 6m)]\r\
    \n# Walking through array\r\
    \nforeach i in=\$ipsec do={\r\
    \n     # Searching IP address of remote host\r\
    \n     :set ipaddr [:pick [/log get \$i message ] 0 ([:len [/log get \$i m\
    essage ]]-30)]\r\
    \n     # Execute if quantity of \"failed to get valid proposal\" records m\
    ore than pop variable\r\
    \n     if ([:len [/log find message~\"failed to get valid proposal.\"]]>=\
    \$pop) do={\r\
    \n         # Execute if IP address isn't in firewall adress-list\r\
    \n         if ([:len [/ip firewall address-list find address=\$ipaddr]]=0 \
    ) do={\r\
    \n             # Supplementation IP to address-list\t\r\
    \n             if (\$ipaddr != \"\") do={\t\r\
    \n                 /ip firewall address-list add list=ipsec-brutforce-from\
    -script address=[:toip \$ipaddr] timeout=7d\r\
    \n                 :log warning \"IPSec_bruteforce_prevention \$ipaddr\"\r\
    \n                  #/tool e-mail send to=\"alerts@mail.srv\" start-tls=tl\
    s-only subject=\"IPSec allert\" body=\"\$ipaddr was blocked because of IPS\
    ec brutforce\"  server=[:resolve mail.srv]\r\
    \n            }\r\
    \n        }\r\
    \n    }\r\
    \n}\r\
    \n\r\
    \n# Searching for \"parsing packet failed, possible cause: wrong password\
    \" string in log.\r\
    \n:set ipsec [/log find message~\"parsing packet failed, possible cause: w\
    rong password\"]\r\
    \n# Walking through array\r\
    \nforeach i in=\$ipsec do={\r\
    \n    # Searching IP address of remote host\r\
    \n    :set ipaddr [:pick [/log get \$i message ] 0 ([:len [/log get \$i me\
    ssage ]]-54)]\r\
    \n    # Execute if quantity of \"parsing packet failed, possible cause: wr\
    ong password\" records more than pop variable\r\
    \n    if ([:len [/log find message~\"parsing packet failed, possible cause\
    : wrong password\"]]>=\$pop) do={\r\
    \n        # Execute if IP address isn't in firewall adress-list\r\
    \n        if ([:len [/ip firewall address-list find address=\$ipaddr]]=0 )\
    \_do={\r\
    \n        # Supplementation IP to address-list\t\r\
    \n        :log warning \"IPSec_bruteforce_prevention \$ipaddr\"\r\
    \n        if (\$ipaddr != \"\") do={\t\r\
    \n            /ip firewall address-list add list=ipsec-brutforce-from-scri\
    pt address=[:toip \$ipaddr] timeout=7d\r\
    \n            #/tool e-mail send to=\"alerts@mail.srv\" start-tls=tls-only\
    \_subject=\"IPSec allert\" body=\"\$ipaddr was blocked because of IPSec br\
    utforce\"  server=[:resolve mail.srv]\r\
    \n            }\r\
    \n        }\r\
    \n    }\r\
    \n}\r\
    \n" policy=read,write,policy,test start-date=jan/01/1970 start-time=\
    05:47:59
