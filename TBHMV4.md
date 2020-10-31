# TBHM V4

## Recon is ❤️

- **Finding Seed/Roots**
    - Scope domain

        looking and uderstanding program scope

    - acquisitions
        - you might drill down to old domains which are vulnerable on an acqustions
    - ASN Enumeration (bhp.he.net)
        - this list a companys ip ranges when it becomes big enough and cloud assent may not include in them
        - Tools
            - Metabigor
            - AsnLookup
            - AMAss
                - it has more than three tool in it
                - we can search in amass intel with asn number and ecen run a port scan in it on any root domain

    - Reverse Whois
        - whoxy.com
        - Domlink
    - Ad/analytics Realationships

        buildwith

    - Google fu
        - Copyright text
        - Terms of service text
        - Privacy policy text
    - Shodan
- **Finding subdomain**
    - Link Discovery
        - Discovery with burp
            - turn off passive scanning
            - forms to auto submit
            - set advanced scope with keywords of target name
            - browse the main site then spider all hosts resursevely
        - Gospider and Hakrawler
        - Subdoaminizer
            - it will look for cloud assets
            - it also has feature to look for hardcoded key using shannon entropy
        - Subscraper

            it has recursion but nokey finding

    - Subdomain Scraping
        - google fu

            site:twitch.tv -www.twitch.tv

        - Amass

            it also corealtes subdomains to asns

        - subfinder v2
        - github-subdomains.py
            - by gwendal le coguic
            - [https://github.com/gwen001/github-search](https://github.com/gwen001/github-search)
        - shosubgo
            - [https://github.com/incogbyte/shosubgo](https://github.com/incogbyte/shosubgo)
            - it gathers aubdomains from shodan

        - cloud ranges
            - scannning whole cloud ranges now and often
            - getttng only 443 and conneecting and looking at certificate data for our domain
            - [http://tls.bufferover.run/dns?q=twitter.com](http://tls.bufferover.run/dns?q=twitter.com)
            - [https://www.daehee.com/scan-aws-ip-ssl-certificates/](https://www.daehee.com/scan-aws-ip-ssl-certificates/)
            - [https://github.com/erbbysam/Hunting-Certificates-And-Servers/blob/master/Hunting Certificates %26 Servers.pdf](https://github.com/erbbysam/Hunting-Certificates-And-Servers/blob/master/Hunting%20Certificates%20%26%20Servers.pdf)

    - Subdomain Bruting
        - Massdns
        - Amass
            - amass enum -brute -d [twitch.tv](http://twitch.tv/) -src
            - amass enum -brute -d twitch.tv -rf
            resolvers.txt -w bruteforce.list
        - aisdnsbrute
            - [https://github.com/blark/aiodnsbrute](https://github.com/blark/aiodnsbrute)
        - Shuffledns
        - Wordlist
            - [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
            - tomnomnom talk
            - commonspeak
        - permutation scanning

            www.$target.com was blocked by waf but ww2.$target.com is not sqli

            [orgin-sub.domain.com](http://orgin-sub.domain.com) and orgin.sub.domain.com to bypass akami

            - altdns
            - amass

- **Port Analysis**
    - masscan  - it only scans ips

        Scaning all open ports

        - masscan -p1-65535 -iL $ipFile --max-rate 1800
        -oG $outPutFile.log
        - [https://danielmiessler.com/study/masscan/](https://danielmiessler.com/study/masscan/)
    - dnmasscan  — takes care of dns resolving

        [https://github.com/rastating/dnmasscan](https://github.com/rastating/dnmasscan)

- **Service scanning**
    - BruteSpray
- **Github Dorking**

    its a script

    - [https://gist.github.com/jhaddix/1fb7ab2409ab579178d2a79959909b33](https://gist.github.com/jhaddix/1fb7ab2409ab579178d2a79959909b33)
- **Screenshoting**
    - [https://github.com/breenmachine/httpscreenshot](https://github.com/breenmachine/httpscreenshot)
    - [https://github.com/FortyNorthSecurity/EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness)
    - Aquatone
- **Subdomain takeover**
    - can i takeover xyz
    - subover
    - nuclei
        - [https://github.com/projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
- **Automation**
    - interlace
        - extend to take different sources of input
        - threading.
        - distribute
        - proxying

    - tomnomnom tools
    - Frameworks
        - C-tier
            - https://github.com/AdmiralGaust/bountyRecon
            - https://github.com/offhourscoding/recon
            - https://github.com/Sambal0x/Recon-tools
            - https://github.com/JoshuaMart/AutoRecon
            - https://github.com/yourbuddy25/Hunter
            - https://github.com/venom26/recon/blob/master/ultimat
            e_recon.sh
            - https://gist.github.com/dwisiswant0/5f647e3d406b5e9
            84e6d69d3538968cd
        - B-tier
            - https://github.com/AdmiralGaust/bountyRecon
            - https://github.com/offhourscoding/recon
            - https://github.com/Sambal0x/Recon-tools
            - https://github.com/JoshuaMart/AutoRecon
            - https://github.com/yourbuddy25/Hunter
            - https://github.com/venom26/recon/blob/master/ultimat
            e_recon.sh
            - https://gist.github.com/dwisiswant0/5f647e3d406b5e9
            84e6d69d3538968cd
        - A-tier
            - findomain
            - Rock-on
            - recon-pipeline
        - S-tier
            - intrigue.io
            - Assetnote
            - spiderfoot
            - project discover