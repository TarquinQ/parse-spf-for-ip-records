# parse_spf.py
# Written in Python 2, will be modded by to be 2->3 compatible later.

# Based on SPF Spec: http://www.openspf.org/SPF_Record_Syntax and https://www.rfc-editor.org/rfc/rfc7208.txt
# Whilst Spec is _relatively_ adhered to, this is designed for a purpose,
#  and should not be considered to be a canonical implementation.
# As per rfc7208, this module does not support "SPF" DNS record type, although it would be quite trivial to add it if required (and to the corresponding DNS module).

import string
from string import split
import get_DNS


_debug_this_module = 0


def set_module_debug(debug_level=0):
    global _debug_this_module
    try:
        _debug_this_module = int(debug_level)
    except:
        _debug_this_module = 0


class IP_Range(object):
    def __init__(self, ip_version, ip_address, subnet_cidr):
        self.ip_version = ip_version
        self.ip_address = ip_address
        self.subnet_cidr = self._parse_cidr(subnet_cidr)

    @classmethod
    def _parse_cidr(cls, cidr):
        actual_subnet = cidr
        if "/" in str(cidr):
            empty_val, actual_subnet = cidr.split("/", 1)
            actual_subnet = int(actual_subnet)
        return actual_subnet

    def to_text(self):
        return str(self.ip_address) + '/' + str(self.subnet_cidr)


def get_ip_records_for_spf_for_domain(domain_with_spf):
    ipv4_permit = []
    ipv6_permit = []
    for ip_range in _get_list_of_permitted_ip_ranges_from_dns(domain_with_spf):
        if not ip_range:  # ie blank
            continue
        if ip_range.ip_version == 4:
            ipv4_permit.append(ip_range.to_text())
        elif ip_range.ip_version == 6:
            ipv6_permit.append(ip_range.to_text())
    return {'ipv4_permit': ipv4_permit, 'ipv6_permit': ipv6_permit}


def _get_list_of_permitted_ip_ranges_from_dns(domain_with_spf):
    valid_spf_init_identifier = 'v=spf1'
    permitted_ip_ranges = []

    for text_record in get_DNS.get_DNS_TXT(domain_with_spf):
        if _debug_this_module > 1: print "Now parsing DNS TXT record: ", text_record

        if not " " in text_record:  # Then it's not an SPF record. This will also filter empty records.
            continue
        token0, spf_record = text_record.split(" ", 1)
        if not token0 == valid_spf_init_identifier:  # Then it's not an SPF record
            continue

        # Special case handling: a Redirect directive, to replace current record with new one.
        if 'redirect=' in spf_record:
            replacement_domain = spf_record.split('redirect=', 1)[1].split(' ')[0]
            if _debug_this_module > 1: print "Now redirecting to new DNS record: ", replacement_domain
            return _get_list_of_permitted_ip_ranges_from_dns(replacement_domain)

        # If we're not replacing:
        for spf_entry in [s for s in spf_record.split(' ') if s]:  # To filter out double-spaces
            if _debug_this_module > 1: print "Now parsing a possible token: ", spf_entry
            new_permitted_ip_ranges = parse_spf_token(spf_entry, domain_with_spf)
            if _debug_this_module > 1: print "IP Ranges from token: ", spf_entry, "are", _convert_list_of_ip_ranges_to_text(new_permitted_ip_ranges)
            permitted_ip_ranges.extend(new_permitted_ip_ranges)

    if _debug_this_module > 1: print "Permitted IP Ranges for domain \"", domain_with_spf, "\" are ", _convert_list_of_ip_ranges_to_text(permitted_ip_ranges)
    return permitted_ip_ranges


def _convert_list_of_ip_ranges_to_text(list_of_ip_ranges):
    text_ranges = []
    for ip_range in list_of_ip_ranges:
        try:
            text_ranges.append(ip_range.to_text())
        except:
            pass
    return text_ranges


def parse_spf_token(orig_token, current_domainname):
    spf_spf_entry_types = ['all', 'ip4', 'ip6', 'a', 'mx', 'include']
    # Ignored_spf_entries = {'exp=', 'exists', 'ptr'}
    ## These entries are ignored as these are runtime-only checks,
    ## and it is not possible to determine statically ahead-of-time.

    spf_mechanism_types = {'+': 'Allow', '-': 'Disallow', '~': 'SoftFail', '?': 'Neutral'}
    spf_mechanism_types_to_ignore = ['-', '~']
    spf_default_decision = '?'  # Neutral

    token = orig_token
    spf_entry = ''
    spf_decision = spf_default_decision
    spf_subnet = '32'
    spf_data__domain_or_IP = current_domainname
    malformed_entry = False

    # Deal with the optional single-char mechanism first
    if token[0] in spf_mechanism_types:
        this_spf_decision = token[0]
        token = token[len(token[0]):]

    # Now we deal with the end of the string in reverse order,
    # chopping chunks off as we go.
    if '/' in token:
        token, subnet = token.split('/', 1)
        try:
            spf_subnet = int(subnet)
        except:
            malformed_entry = True
        if '/' in token:
            # Sanity check - there should only ever be a single '/' char
            malformed_entry = True

    if ':' in token:
        token, spf_data__domain_or_IP = token.split(':', 1)
        if ':' in token:
            # Sanity check - there should only ever be a single ':' char
            malformed_entry = True

    # Now we should only have an spf_entry left in the token string
    if token not in spf_spf_entry_types:
        malformed_entry = True
    else:
        spf_entry = token

    if _debug_this_module > 3: print [orig_token, token, spf_entry, spf_decision, spf_subnet, spf_data__domain_or_IP, malformed_entry]

    # Now we should only have an valid data
    if malformed_entry:
        return []
    elif spf_decision in spf_mechanism_types_to_ignore:
        return []
    else:
        return parse_valid_spf_token(spf_entry, spf_decision, spf_subnet, spf_data__domain_or_IP)


def parse_valid_spf_token(spf_entry, spf_decision, spf_subnet, spf_data__domain_or_IP):
    #spf_spf_entry_types = ['all', 'ip4', 'ip6', 'a', 'mx', 'ptr', 'include']
    ret_list = []
    if spf_entry == 'all':
        add_to_list = parse_spf_entry_all(spf_entry, spf_decision, spf_subnet, spf_data__domain_or_IP)
        if add_to_list:
            ret_list.extend(add_to_list)
    elif spf_entry == 'ip4':
        add_to_list = parse_spf_entry_ip4(spf_entry, spf_decision, spf_subnet, spf_data__domain_or_IP)
        if add_to_list:
            ret_list.extend(add_to_list)
    elif spf_entry == 'ip6':
        add_to_list = parse_spf_entry_ip6(spf_entry, spf_decision, spf_subnet, spf_data__domain_or_IP)
        if add_to_list:
            ret_list.extend(add_to_list)
    elif spf_entry == 'a':
        add_to_list = parse_spf_entry_a(spf_entry, spf_decision, spf_subnet, spf_data__domain_or_IP)
        if add_to_list:
            ret_list.extend(add_to_list)
    elif spf_entry == 'mx':
        add_to_list = parse_spf_entry_mx(spf_entry, spf_decision, spf_subnet, spf_data__domain_or_IP)
        if add_to_list:
            ret_list.extend(add_to_list)
    elif spf_entry == 'include':
        add_to_list = _get_list_of_permitted_ip_ranges_from_dns(spf_data__domain_or_IP)
        if add_to_list:
            ret_list.extend(add_to_list)
    return ret_list


def parse_spf_entry_all(spf_entry, spf_decision, spf_subnet, spf_data__domain_or_IP):
    if spf_decision == '+':
        return [IP_Range(4, '0.0.0.0', 0), IP_Range(6, '00::00', 0)]
    else:
        return []


def parse_spf_entry_ip4(spf_entry, spf_decision, spf_subnet, spf_data__domain_or_IP):
    return [IP_Range(4, spf_data__domain_or_IP, spf_subnet)]


def parse_spf_entry_ip6(spf_entry, spf_decision, spf_subnet, spf_data__domain_or_IP):
    return [IP_Range(6, spf_data__domain_or_IP, spf_subnet)]


def parse_spf_entry_a(spf_entry, spf_decision, spf_subnet, spf_data__domain_or_IP):
    ret_list = []

    for A_record in get_DNS.get_DNS_A(spf_data__domain_or_IP):
        ret_list.append(IP_Range(6, A_record, spf_subnet))

    for QuadA_record in get_DNS.get_DNS_AAAA(spf_data__domain_or_IP):
        ret_list.append(IP_Range(6, QuadA_record, spf_subnet))

    return ret_list


def parse_spf_entry_mx(spf_entry, spf_decision, spf_subnet, spf_data__domain_or_IP):
    ret_list = []
    for A_record in get_DNS.get_DNS_MX(spf_data__domain_or_IP):
        ret_list.extend(parse_spf_entry_a(spf_entry, spf_decision, spf_subnet, spf_data__domain_or_IP))
    return ret_list


if __name__ == "__main__":
    domain_to_resolve = 'mimecast.com'
    print get_ip_records_for_spf_for_domain(domain_to_resolve)
