# test_parse_spf.py
# Written in Python 2, will be modded by to be 2->3 compatible later.

# This tests parse_spf.py
# Technically, I should write these tests in such a way that a stated domain-to-check
# has a known set of outcomes. But, that'd require test-harnessing the DNS code, and
# that's too much work for this small thing, so I just throw a bunch of live domains
# at it, and make sure it doesn't die on any ofthe code parsing.

import parse_spf


def testme(domain_to_resolve):
    print "IPs in SPF for domain " + domain_to_resolve + " is:"
    print parse_spf.get_ip_records_for_spf_for_domain(domain_to_resolve)


parse_spf.set_module_debug(1)

domain_to_resolve = 'mimecast.com'
testme(domain_to_resolve)

domain_to_resolve = 'spf.protection.outlook.com'
testme(domain_to_resolve)

domain_to_resolve = 'google.com'
testme(domain_to_resolve)

domain_to_resolve = 'gmail.com'
testme(domain_to_resolve)

domain_to_resolve = 'hotmail.com'
testme(domain_to_resolve)

domain_to_resolve = 'microsoft.com'
testme(domain_to_resolve)

domain_to_resolve = 'apple.com'
testme(domain_to_resolve)

domain_to_resolve = 'hooli.xyz'
testme(domain_to_resolve)


