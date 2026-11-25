# Case Study: The Mirai IoT Botnet (2016)

*Group secureTeam · Class IIOT-B2 · IIOT Security [ARI421] · Faculty: Mr. Arun Kumar ·
Team: Vansh Dabas (09519051723), Sadia Mohd. Khan (12219051723),
Abubakar Siddiqui (08019051723), Vedant Mishra (11819051723) · Case study owner (Module 4): Vedant Mishra*

This case study looks at a real IoT security incident, the Mirai botnet of 2016, and
compares it with our simulated Smart Building (SecureIoT-Sim). Mirai is a good match
for our project: it broke into cheap, always-on devices with weak passwords, which is
exactly what our brute-force attack does to the insecure baseline, and it used those
devices to flood other systems, which our flooding attacks imitate on a small scale.

## 1. Incident overview

Mirai ("the future" in Japanese) is malware that turns Linux-based IoT devices, mainly
IP cameras, digital video recorders (DVRs) and home routers, into a remotely controlled
army of "bots". Security researchers from the MalwareMustDie group first described it in
August 2016. Within weeks it had infected hundreds of thousands of devices. At its peak,
about 600,000 devices were infected [1].

Mirai did not use an advanced exploit. It logged in with factory-default usernames and
passwords over Telnet, a remote-login service that sends everything, including
passwords, in plain text. Once inside, it waited for orders from the attackers and
then flooded its target with traffic. This is called a distributed denial-of-service
(DDoS) attack.

Between September and November 2016, Mirai caused some of the largest DDoS attacks ever
recorded up to that time:

* the security blog KrebsOnSecurity (about 620 Gbit/s);
* the French hosting company OVH (about 1 Tbit/s);
* the DNS provider Dyn. This attack made popular websites such as Twitter, Netflix,
  Reddit, GitHub and Spotify unreachable for many users in the United States and
  Europe for several hours [1][3][4].

## 2. Timeline

| Date | Event |
|---|---|
| August 2016 | MalwareMustDie publicly describes the new Linux malware "Mirai" [1]. |
| 20 September 2016 | KrebsOnSecurity is hit by a DDoS of about 620 Gbit/s; the site is moved to Google's Project Shield [5]. |
| Late September 2016 | OVH reports attacks of about 1 Tbit/s from roughly 145,000 hacked cameras and DVRs [1]. |
| 30 September 2016 | The full Mirai source code is published on a hacking forum by a user called "Anna-senpai". Copies and variants spread quickly [1][2]. |
| 14 October 2016 | US-CERT issues alert TA16-288A, "Heightened DDoS Threat Posed by Mirai and Other Botnets" [3]. |
| 21 October 2016 | Dyn's managed DNS service is attacked in several waves. Many large websites become unreachable for hours [4]. |
| October 2016 | Webcam maker Hangzhou Xiongmai recalls some of its cameras sold in the US, whose default passwords Mirai abused [2]. |
| November 2016 | A Mirai variant attacks home routers through a remote-management port (TCP 7547). About 900,000 Deutsche Telekom customers lose internet access [1]. |
| 13 December 2017 | Three young US men admit in court that they created and operated Mirai [6]. |

## 3. Systems and devices affected

* **Directly infected:** internet-connected IP cameras, DVRs and network video
  recorders, home routers and similar embedded Linux devices from many manufacturers.
  These devices had Telnet open to the internet and shipped with the same default login
  on every unit [1][2].
* **Targets of the floods:** websites (KrebsOnSecurity), hosting providers (OVH),
  internet infrastructure (Dyn's DNS servers) and, through Dyn, every service that used
  Dyn to answer DNS queries [4].
* **Owners:** most owners never noticed the infection. The device kept working normally
  while it attacked others in the background.

## 4. Attack vector and techniques used

Mirai's life cycle had five steps [1][2]:

1. **Scanning:** each bot sent probes to random IPv4 addresses, looking for open
   Telnet ports (TCP 23 and 2323).
2. **Brute-force login:** when it found one, it tried a built-in list of 62 default
   username/password pairs (for example `root/xc3511`, `admin/admin`, `root/vizxv`).
3. **Reporting and loading:** a working login was reported to a "report server". A
   separate "loader" logged in, detected the CPU type (ARM, MIPS, x86 and others) and
   installed the matching Mirai binary.
4. **Holding the device:** the bot ran only in memory, deleted its own file, and killed
   other programs listening on ports 22, 23 and 80, so that competing malware (and the
   owner) could not get back in through those services.
5. **Attacking:** the bot waited for commands from a command-and-control (C2) server,
   then launched floods. The code had about ten flood types, including UDP, TCP SYN
   and ACK, GRE, HTTP, and DNS "water torture" (random sub-domain) floods.

Mirai also kept a hard-coded list of IP ranges it would not scan, for example the US
Department of Defense and the US Postal Service, to avoid attention [2].

## 5. Vulnerabilities exploited

| Weakness | Explanation |
|---|---|
| Default, shared credentials | Thousands of devices of one model had the same factory login. Many owners could not change it, or did not know they should. |
| Unnecessary, insecure service exposed | Telnet was enabled and reachable from the whole internet. It has no encryption and no built-in protection against guessing. |
| No limit on login attempts | Devices accepted unlimited wrong passwords, so trying 62 pairs took seconds. |
| No device identity or authentication of commands | The infected device obeyed any controller that logged in; nothing proved who was giving the orders. |
| No monitoring | Nobody noticed thousands of failed logins or the sudden outgoing floods. |
| No secure update path | Many devices could not be patched remotely, so the hole stayed open. Rebooting removed Mirai from memory, but the device was usually reinfected within minutes. |
| Missing egress filtering | Networks let hacked devices send huge amounts of attack traffic outwards. |

## 6. Impact

* **Availability:** in the Dyn attack, major websites and services were unreachable or
  slow for many users for hours [4].
* **Economic:** providers had to absorb or mitigate traffic at the terabit scale.
  Businesses lost revenue during the outages. Deutsche Telekom's router outage affected
  about 900,000 customers [1].
* **Security community:** the publication of the source code meant that anyone could
  build their own botnet. Many Mirai variants are still active today [1][2].
* **Policy:** Mirai became the standard example used to argue for minimum security rules
  for IoT products. These include California's law SB-327 (in force since 2020), which
  bans universal default passwords; the European standard ETSI EN 303 645 (2020); and
  the UK's product-security law (in force since 2024) [7].

## 7. Detection and response

* **Detection:** researchers saw the scanning in internet telescopes and honeypots, which
  are decoy devices that record login attempts. The large attacks were detected by the
  victims' network monitoring [1].
* **Mitigation:** the victims moved to DDoS-protection services (Krebs to Project Shield)
  and filtered traffic at the network edge. Dyn worked with upstream providers to absorb
  the attack waves [4][5].
* **Advisories and recalls:** US-CERT published alert TA16-288A [3]. It recommended
  changing default passwords, disabling Telnet/SSH where not needed and updating
  firmware. Xiongmai recalled some cameras [2].
* **Legal:** in December 2017 the US Department of Justice announced that three men had
  pleaded guilty to creating and operating Mirai [6].

## 8. Mapping to our project

### 8.1 Which of our simulated attacks resembles this incident

| Mirai step | Our attack in SecureIoT-Sim | What happened in our INSECURE building |
|---|---|---|
| Brute-force login with a list of common passwords | `brute_force`: tries 99 common passwords against `operator1` | Account taken over at guess 59 (`sunshine1`). There is no limit and no lockout, and the reply even says whether the username exists. |
| Logging in to devices that trust anyone | `spoofing`: a fake client claims to be sensor `temp-01` | The broker accepted the fake device; its readings were stored by the cloud (10/10). |
| Plain-text Telnet sessions | `sniffing`: listening to traffic on the building network | Every reading and command was readable (20/20). |
| Obeying commands from an attacker's C2 server | `unauthorised_command`: a viewer, no login, a forged token, and a rogue client all try to unlock a door | All 4 routes opened `lock-02`. |
| Flooding a target | `flooding_broker` (1000 messages from a hijacked energy meter) and `flooding_api` (300 requests from 10 threads) | 100% of the flood was accepted, with no limit and no alert. |

### 8.2 Which of our defences would have prevented or limited it

| Mirai weakness | Our defence (secure mode) | Measured result in our test |
|---|---|---|
| Default, shared credentials | Each device gets its own random 256-bit key at registration, and keys are stored encrypted. Users' passwords are bcrypt-hashed, and a password policy blocks weak new passwords. | Spoofing: challenge-response failed (wrong key), 0/10. |
| Unlimited guessing | Account lockout after 5 wrong passwords (HTTP 423), a login rate limit (HTTP 429), and the same error for unknown users. | Brute force: 0/99. Replies were 401 ×5, 423 ×5, 429 ×89. The account was not taken over, even though the weak password was in the list. |
| Plain-text protocol | AES-256-GCM encryption plus HMAC-SHA256 on every message, with sequence numbers and timestamps. | Sniffing 0/20, tampering 0/10, replay 0/5. |
| Devices obey any controller | Door commands must carry an ECDSA signature from the cloud. A topic ACL at the gateway, JWT logins and role-based access control apply on top. | Unauthorised command: 0/4 (HTTP 403, HTTP 401, 401, and the rogue client was refused at the gateway). |
| Flooding | A token-bucket rate limit per device at the gateway and per user at the API. | Broker flood: 20/1000 accepted (2%). API flood: about 12% accepted. Both raised alerts. |
| No monitoring | Audit log with alert rules ("Possible password brute force", "Account locked", "Device flooding the gateway", …) on the admin dashboard. | 13 alerts raised during one secure run. |
| Infected devices cannot be cleaned | Key rotation and revocation: a revoked device is disconnected and refused at the gateway, and can be re-registered with a new key. | Revoked `motion-02` was refused on reconnect, and came back on key v2 after re-registration. |

### 8.3 What our simulation does not cover

* **Internet-wide scanning and real Telnet/SSH services.** Our devices only speak our
  own protocol on `127.0.0.1`, so there is no open remote-login service to scan for.
* **Outgoing attacks from the building.** Mirai's victims were third parties. We rate
  limit traffic coming *into* our gateway, but we do not simulate egress filtering of
  traffic going *out* of the building.
* **Malware on the device itself.** We model the network and cloud. We do not model
  firmware, memory-resident malware or a secure firmware-update process.
* **Terabit-scale volume.** A rate limiter protects one gateway and one API. It cannot
  absorb a 1 Tbit/s flood. That needs upstream DDoS protection, as Krebs and Dyn used.
* **Network segmentation.** In a real building the IoT devices would sit on their own
  network segment (VLAN) behind a firewall. Our simulation runs on one machine.

## 9. Lessons learned

1. **No default or shared credentials.** Every device needs its own identity. In our
   project this is a random per-device key and challenge-response, which is what
   ETSI EN 303 645 and SB-327 now require.
2. **Switch off what you do not need.** Telnet should never have been reachable from the
   internet. Expose as few services as possible.
3. **Limit and watch login attempts.** Lockout and rate limiting turn a seconds-long
   brute force into a failure, and alerts tell the operator it is happening.
4. **Encrypt and authenticate everything.** Plain-text management protocols leak
   passwords and let attackers inject commands.
5. **Plan for compromise.** Devices must be updatable, and the operator must be able to
   revoke a hacked device and re-register it with a new key.
6. **Defend in depth and share responsibility.** Manufacturers (secure defaults),
   network operators (egress filtering, DDoS protection) and users (changing passwords,
   updating) each have a part to play. No single control would have stopped Mirai on
   its own.

## 10. References

1. M. Antonakakis et al., "Understanding the Mirai Botnet," in *Proc. 26th USENIX
   Security Symposium*, Vancouver, Canada, Aug. 2017, pp. 1093–1110.
2. C. Kolias, G. Kambourakis, A. Stavrou and J. Voas, "DDoS in the IoT: Mirai and Other
   Botnets," *Computer*, vol. 50, no. 7, pp. 80–84, 2017.
3. US-CERT, "Heightened DDoS Threat Posed by Mirai and Other Botnets," Alert TA16-288A,
   14 Oct. 2016.
4. S. Hilton, "Dyn Analysis Summary of Friday October 21 Attack," Dyn (Oracle) blog,
   26 Oct. 2016.
5. B. Krebs, "KrebsOnSecurity Hit With Record DDoS," *KrebsOnSecurity*, Sept. 2016.
6. U.S. Department of Justice, Office of Public Affairs, "Justice Department Announces
   Charges and Guilty Pleas in Three Computer Crime Cases Involving Significant DDoS
   Attacks," press release, 13 Dec. 2017.
7. ETSI, "Cyber Security for Consumer Internet of Things: Baseline Requirements,"
   ETSI EN 303 645 V2.1.1, June 2020.
