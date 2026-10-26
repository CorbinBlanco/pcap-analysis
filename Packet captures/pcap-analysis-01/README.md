# PCAP Analysis #1 — First to Last

This write-up documents my analysis of the **August 9, 2026 “First to Last” traffic-analysis exercise** from [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/2026/08/09/index.html). I used Wireshark to trace traffic associated with FormBook alerts to a Windows client and identify its computer and user accounts.

This is a public training exercise, none of this is real.

## Investigation objectives

The exercise asks for five details about the infected Windows client:

- IP address
- MAC address
- Hostname / computer name
- User account name
- User's full name

**The background of this analysis was stated on the website and is as follows:**

```
You're covering a shift for an analyst at your organization's Security Operations Center (SOC). You see the following alerts:

02:13 UTC - ET MALWARE FormBook CnC Checkin (GET) - 172.64.155[.]76:80
02:14 UTC - ET MALWARE FormBook CnC Checkin (GET) - 146.59.71[.]167:80
02:14 UTC - ET MALWARE FormBook CnC Checkin (GET) - 38.182.168[.]246:80
02:15 UTC - ET MALWARE FormBook CnC Checkin (GET) - 45.130.41[.]161:80
02:15 UTC - ET MALWARE FormBook CnC Checkin (GET) - 172.67.162[.]153:80
02:16 UTC - ET MALWARE FormBook CnC Checkin (GET) - 121.54.163[.]148:80

This is followed by further alerts for FormBook CnC Checkin for the next few minutes.

You retrieve a packet capture (pcap) of traffic during the time of the alert, and you intend to identify that infected host.

The characteristics of your environment are:

LAN segment range:  172.16.8[.]0/24   (172.16.8[.]0 through 172.16.8[.]255)
Domain:  firsttolast[.]tech
AD environment name:  FIRSTTOLAST
Active Directory (AD) domain controller:  172.16.8[.]2 - FIRSTTOLAST-DC
LAN segment gateway:  172.16.8[.]1
LAN segment broadcast address:  172.16.8[.]255
```

## 1. Start with the alert destinations

My first question was: **Which internal device is sending the traffic associated with the alerts?**

In the analysis background, all of the alerts were at port 80, which is the port for HTTP. So I filtered HTTP requests to the destination IP addresses listed in the exercise.

```wireshark
http.request && ip.dst in {172.64.155.76, 146.59.71.167, 38.182.168.246, 45.130.41.161, 172.67.162.153, 121.54.163.148}
```

The matching requests repeatedly showed `172.16.8.49` as the source. This gave me the address of the infected computer and a IP address to use for the rest of the exercise.

The screenshot below shows multiple GET and POST requests from that client and the details of one of the packets that was sent.

![](screenshots/01-http-client-and-mac.png)

## 2. Identify the client's MAC address

By examining the details of a packet sent by that client, I can see the MAC address by looking at the Ethernet II header
```text
IPv4 source: 172.16.8.49
Ethernet source: 00:12:f0:28:d4:34
```

The client's MAC address is `00:12:f0:28:d4:34`.

## 3. Inspect HTTP exchanges

Now that I have the IP address and MAC address, I decided to do a deeper inspections on the HTTP exchanges.

For each GET request, I used **Follow -> TCP Stream**. I found that the user agent was Firefox on a Windows Device and that there was a different host for each GET request:
```
www.legenda-sochi.com\r\n
www.21207628.shop
www.grinswabebthu.info\r\n
www.taibeinan.cc\r\n
www.titatnium303.com\r\n
www.independent.ie\r\n
```

For each device that the infected computer contacted, a 404 error was the response, meaning that there was no successful connection between any malware and the contacted devices.

## 4. Find the hostname through Kerberos

Next, I wanted to identify the Windows computer behind `172.16.8.49`.

An NTLM search returned no results, so I moved to Kerberos:

```wireshark
ip.addr == 172.16.8.49 && kerberos
```

In **frame 1939**, a Kerberos AS-REQ from `172.16.8.49` to `172.16.8.8`, I expanded:

**Kerberos -> as-req -> req-body -> addresses**

The Kerberos host-address field showed `DESKTOP-5NLV63K`, supporting the computer name.

![Kerberos AS-REQ showing the computer account and hostname for 172.16.8.49](screenshots/02-kerberos-hostname.png)

**Finding:** The hostname / computer name is `DESKTOP-5NLV63K`.

## 6. Match the account to the user's full name

To find the full name and user account, I examined SAMR account-information traffic involving the client:
```wireshark
samr && ip.addr == 172.16.8.49
```
In a QueryUserInfo respone packet from `172.16.8.8` to `172.16.8.49`(infected computer), I found **Account Name** and **Full Name**. Expanding both fields revealed the username and the full name of the client.
```text
Account Name: rvance
Full Name: Raymond Vance
```

![SAMR QueryUserInfo response mapping rvance to Raymond Vance](screenshots/03-samr-user-full-name.png)

**Finding:** The user account is `rvance`, and the associated full name is **Raymond Vance**.

## Evidence summary
| Item | Finding |
|---|---|
| Infected client IP | `172.16.8.49` |
| Client MAC address | `00:12:f0:28:d4:34` |
| Hostname / computer name | `DESKTOP-5NLV63K` |
| User account | `rvance` |
| User's full name | Raymond Vance |

## Source and attribution

- [First to Last — exercise background and original capture](https://www.malware-traffic-analysis.net/2026/08/09/index.html)
- [Wireshark Kerberos field reference](https://www.wireshark.org/docs/dfref/k/kerberos.html)
- [Wireshark SAMR field reference](https://www.wireshark.org/docs/dfref/s/samr.html)
