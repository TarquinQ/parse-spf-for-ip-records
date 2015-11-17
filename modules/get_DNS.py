import dns.resolver


def get_DNS_TXT(record_to_resolve):
    ret_list = list()
    answers = get_DNS_Record(record_to_resolve, 'TXT')
    for response_data in answers:
        for txt_record in response_data.strings:
            ret_list.append(txt_record)
    return ret_list


def get_DNS_MX(record_to_resolve):
    ret_list = list()
    answers = get_DNS_Record(record_to_resolve, 'MX')
    for response_data in answers:
        ret_list.append(response_data.exchange.to_text())
    return ret_list


def get_DNS_A(record_to_resolve):
    ret_list = list()
    answers = get_DNS_Record(record_to_resolve, 'A')
    for response_data in answers:
        ret_list.append(response_data.address)
    return ret_list


def get_DNS_AAAA(record_to_resolve):
    ret_list = list()
    answers = get_DNS_Record(record_to_resolve, 'AAAA')
    for response_data in answers:
        ret_list.append(response_data.address)
    return ret_list


def get_DNS_Record(record_to_resolve, record_type):
    answers = []
    try:
        answers = dns.resolver.query(record_to_resolve, record_type)
    except dns.resolver.Timeout as Timeout:
        # No answers could be found in the specified lifetime
        print 'DNS Error: Timeout'
    except dns.resolver.NXDOMAIN as NXDOMAIN:
        # the query name does not exist
        print 'DNS Error: NXDomain'
    except dns.resolver.YXDOMAIN as YXDOMAIN:
        # the query name is too long after DNAME substitution
        print 'DNS Error: YXDomain'
    except dns.resolver.NoAnswer as NoAnswer:
        # the response did not contain an answer and raise_on_no_answer is True.
        print 'DNS Error: NoAnswer'
    except dns.resolver.NoNameservers as NoNameServers:
        # no non-broken nameservers are available to answer the question.
        print 'DNS Error: No Name Servers'
    except:
        print("Unexpected error occurred: ", sys.exc_info()[0])
        print("Please try again.")
    return answers

