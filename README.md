# Parse-spf-for-ip-records
!!Overview
Parses an SPF record in DNS and produces a set of ipv4 and ipv6 records.
This aims to be a small & simple implementation, but one still able to handle input as per RFC and handle errors gracefully.

!!Approach
The fundamental idea is to parse public DNS TXT records for a domain, parse it to get all permitted A/MX/IPv{4,6} records,
and produce a set of IPv4 or v6 IP ranges (one per text-output line).

!!Usage
Written in pure python (with dnspython modules installed), and designed to be both embeddable as a library and usable via unix shell script.
This should take in a Domain Name and IP_ ersion (ie 4 or 6) as arguments, and produce a list of corresponding IP addresses.

!!Use Case
My use case is to parse an SPF record into iptables Allow rules - the script should produce a set of records that can be
directly used inside iptables rules to ACCEPT a new TCP connection. This will allow relay from a trusted third-party
SMTP-based email/spam/virus front-end filter (eg Mimecast, Office 365) into an internal host whilst denying all other connections.

Other use cases include access and relay rules on postfix(/sendmail/other smtp), and I have seen examples of spam-Whitelisting
based on IP (eg allow all gmail.com_spf-validated-IPs to send email).

!!Future Usage
At the moment the scope is simply to produce a whitelisted set of Allowed IPs; a future aim could include
producing a set of Denied IPs as well.

!!Project Status
The project is currently under initial development. The aim is clear and scope relatively small, so do expect completion. :)

!!Contributions
Contributions will be accepted, although I'd like to get the initial code written & committed first.
Things that I won't be writing, but will gladly accept as contributions (inside a project sub-directory)
will include postfix/sendmail config snippets and bash shell scripts to parse output.
