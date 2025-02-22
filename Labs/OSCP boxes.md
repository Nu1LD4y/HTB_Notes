# OSCP Boxes Checklist

## Easy

- [x]  Active (windows): This is a box about group.xml and kerberoast
- [ ]  Armageddon (Linux)
- [x]  Bashed (Linux):  This is a easy machine to practice php reverseshell
- [x]  Bastion (Windows) :  This box is about .vhd file mou~~nting, sam file [secreatdump.py](http://secreatdump.py) dump hash an~~d mRemoteNG config file decrypt
- [x]  Beep (Linux)
- [ ]  Blocky (Linux)
- [ ]  Blunder (Linux)
- [x]  Bounty (Windows):file upload with web.config and abuse SeImpersonate with juicy-potato
- [ ]  Bust (Windows)
- [x]  Delivery (Linux)
- [ ]  Devel (Windows)
- [x]  Doctor (Linux): log analysis , SSTI
- [x]  Forest (Windows): asproasting, dcsync, bloodhound, golden ticket
- [x]  FriendZone (Linux) : this machine start with a very ctf like situation, but it started to become interesting after finding LFI vuln .
- [ ]  Frolic (Linux)
- [ ]  Grandpa (Windows): IIS
- [ ]  Granny (Windows)
- [ ]  Horizontall (Linux)
- [ ]  Irked (Linux)
- [ ]  Jerry (Windows)
- [ ]  Knife (Linux)
- [ ]  Love (Windows)
- [x]  Legacy (Windows): ms17-010
- [ ]  Luanne (Other)
- [ ]  Mirai (Linux)
- [ ]  Networked (Linux)
- [ ]  Nibbles (Linux)
- [ ]  Omni (Windows)
- [ ]  OpenAdmin (Linux)
- [ ]  Optimum (Windows)
- [ ]  Previse (Linux)
- [ ]  Postman (Linux)
- [ ]  Remote (Windows)
- [ ]  ScriptKiddie (Linux)
- [ ]  Sense (FreeBSD)
- [ ]  ServerMon (Windows)
- [x]  Shocker (Linux): bad machine, you need to find /cgi-bin/user.sh (-x sh,cgi,pl)then shellshock
- [ ]  Sunday (Solaris)
- [ ]  Support (Windows)
- [ ]  Swagshop (Linux)
- [ ]  Traverxec (Linux)
- [ ]  Tabby (Linux)
- [ ]  Valentine (Linux)

## Medium

- [x]  Authority (Windows): web-based service pwm, Test LDAP Profile get svc_ldap password, attack ADCS and get admin.
- [ ]  Bastard (Windows)
- [ ]  Chatterbox (Windows)
- [ ]  Cronos (Linux)
- [ ]  Forge (Linux)
- [ ]  Fuse (Windows)
- [ ]  Haircut (Linux)
- [ ]  Intelligence (Windows)
- [ ]  Jarvis (Linux)
- [ ]  Magic (Linux)
- [ ]  Mango (Linux)
- [ ]  Nineneh (Linux)
- [ ]  Node (Linux)
- [ ]  Ophiuchi (Linux)
- [ ]  Passage (Linux)
- [ ]  Pit (Linux)
- [ ]  Poison (Linux)
- [ ]  Popcorn (Linux)
- [ ]  Ready (Linux)
- [ ]  Seal (Linux)
- [ ]  SecNotes (Windows)
- [ ]  Shiboleth (Linux)
- [ ]  Silo (Windows)
- [ ]  SolidState (Linux)
- [ ]  SneakyMailer (Linux)
- [ ]  Tartarsauce (Linux)
- [ ]  Worker (Windows)
- [ ]  Writer (Linux)

## Hard

- [ ]  Conceal (Windows)
- [ ]  Object (Windows)

## Insane

- [ ]  APT (Windows)
- [ ]  Bankrobber (Windows)
- [ ]  Brainfuck (Linux)

## More Challenging

- [ ]  Atom (Windows) - Medium
- [ ]  Bart (Windows) - Medium
- [ ]  Bitlab (Linux) - Medium
- [ ]  Blackfield (Windows) - Hard
- [ ]  Book (Linux) - Medium
- [ ]  Breadcrumbs (Windows) - Hard
- [x]  Cascade (Windows) - Medium: smb null session, ldap null session, user enum, ldap enum, password attritube, check shares, see vnc password, see new share, get new creds, get new share, debugger exe with dnspy and get bin priv user, get deleted item, get admin pwd.
- [ ]  Control (Windows) - Hard
- [ ]  DevOops (Linux) - Medium
- [ ]  Dynstr (Linux) - Medium
- [ ]  Falafel (Linux) - Hard
- [ ]  Hawk (Linux) - Medium
- [ ]  Jail (Linux) - Insane
- [ ]  Jeeves (Windows) - Medium
- [ ]  Kotarak (Linux) - Hard
- [ ]  LaCasaDePapel (Linux) - Easy
- [ ]  Lightweight (Linux) - Medium
- [ ]  Mango (Linux) - Medium
- [ ]  Monitors (Linux) - Hard
- [ ]  Monteverde (Windows) - Medium
- [ ]  Nest (Windows) - Easy
- [ ]  Netmon (Windows) - Easy
- [ ]  October (Linux) - Medium
- [ ]  Pikaboo (Linux) - Hard
- [ ]  Pivotapi (Windows) - Insane
- [ ]  Querier (Windows) - Medium
- [ ]  Quick (Linux) - Hard
- [ ]  Safe (Linux) - Easy
- [ ]  Sauna (Windows) - Easy
- [ ]  Sizzle (Windows) - Insane
- [x]  Sniper (Windows) - Medium:  user rfi with smb to load a php shell, then use db.php to get first credential. Find a .chm file in DOC folder which admin will interact with it, exploit it with nishang client chm and get root
- [ ]  Stacked (Linux) - Insane
- [ ]  Tally (Windows) - Hard
- [x]  Resolute (Windows) - Medium : user enum and get common password in user description. login and find PSTranscripts which log input and output. get another user in DNS admin, build dnscmd runnable base on .net version in C:\windows\[microsoft.net](http://microsoft.net/)\Framework64, get system reverse shell.