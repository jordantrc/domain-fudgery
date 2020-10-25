#!/usr/bin/env python3
#
# fudge-domain.py
#
# Finds potentially useful domains
# which are visually similar to the 
# target domain and ascertains whether
# these domains are currently available
# (not registered). Also checks if any TLDs
# are not registered for the domain.
#
# Usage:
# domain-fudgery.py [options] [domain]
# Only works with second-level domain names, 
# e.g. google.com, amazon.co.uk
#
# OPTIONS:
#
# TLD Options:
#    --country-code-tlds     check country code TLDs
#    --original-tlds         check original TLDs (.com, .net, .org)
#    --custom-tlds           check additional list of TLDS, comma separated
#
# General Options:
#    --file                  load domains from the given filename
#                            one domain per line
#    --no-active             use only passive checks
#    --no-whois              do not perform whois checks
#

import argparse
import itertools
import os
import sys
from dns import name
from dns import message


CHARACTER_LOOK_ALIKES = {
    'a': ['d'],
    'A': ['4'],
    'b': ['1o', 'lo'],
    'B': ['8'],
    'd': ['ol', 'o1'],
    'E': ['3'],
    'i': ['1', 'l'],
    'I': ['1', 'l'],
    'l': ['1', 'i'],
    'm': ['rn'],
    'o': ['0'],
    'O': ['0'],
    'Q': ['O'],
    's': ['5'],
    'S': ['5'],
    'T': ['7'],
    'w': ['vv'],
    'W': ['VV'],
    'z': ['2'],
    'Z': ['2'],
    '0': ['O'],
    '1': ['l'],
    '2': ['Z'],
    '4': ['A'],
    '5': ['S'],
    '7': ['T'],
    '8': ['B']
}

# original TLDs, does not include restricted-use
# TLDs .edu, .gov, .mil, .int
TLDS_ORIGINAL = ['.com', '.net', '.org']

# country code TLDs
TLDS_COUNTRY_CODE = [
    '.ac','.ad','.ae','.af','.ag','.ai','.al','.am','.ao','.aq','.ar','.as','.at','.au','.aw','.ax',
    '.az','.ba','.bb','.bd','.be','.bf','.bg','.bh','.bi','.bj','.bm','.bn','.bo','.bq','.br','.bs',
    '.bt','.bw','.by','.bz','.ca','.cc','.cd','.cf','.cg','.ch','.ci','.ck','.cl','.cm','.cn','.co',
    '.cr','.cu','.cv','.cw','.cx','.cy','.cz','.de','.dj','.dk','.dm','.do','.dz','.ec','.ee','.eg',
    '.eh','.er','.es','.et','.eu','.fi','.fj','.fk','.fm','.fo','.fr','.ga','.gd','.ge','.gf','.gg',
    '.gh','.gi','.gl','.gm','.gn','.gp','.gq','.gr','.gs','.gt','.gu','.gw','.gy','.hk','.hm','.hn',
    '.hr','.ht','.hu','.id','.ie','.il','.im','.in','.io','.iq','.ir','.is','.it','.je','.jm','.jo',
    '.jp','.ke','.kg','.kh','.ki','.km','.kn','.kp','.kr','.kw','.ky','.kz','.la','.lb','.lc','.li',
    '.lk','.lr','.ls','.lt','.lu','.lv','.ly','.ma','.mc','.md','.me','.mg','.mh','.mk','.ml','.mm',
    '.mn','.mo','.mp','.mq','.mr','.ms','.mt','.mu','.mv','.mw','.mx','.my','.mz','.na','.nc','.ne',
    '.nf','.ng','.ni','.nl','.no','.np','.nr','.nu','.nz','.om','.pa','.pe','.pf','.pg','.ph','.pk',
    '.pl','.pm','.pn','.pr','.ps','.pt','.pw','.py','.qa','.re','.ro','.rs','.ru','.rw','.sa','.sb',
    '.sc','.sd','.se','.sg','.sh','.si','.sk','.sl','.sm','.sn','.so','.sr','.ss','.st','.su','.sv',
    '.sx','.sy','.sz','.tc','.td','.tf','.tg','.th','.tj','.tk','.tl','.tm','.tn','.to','.tr','.tt',
    '.tv','.tw','.tz','.ua','.ug','.uk','.us','.uy','.uz','.va','.vc','.ve','.vg','.vi','.vn','.vu',
    '.wf','.ws','.ye','.yt','.za','.zm'
    ]

# country codes with restricted second level domains (individuals or companies can
# only register third level domains)
TLDS_COUNTRY_CODE_RESTRICTED_LVL2 = [
    '.au','.bn','.bt','.cy','.et','.fk','.gh','.gn','.gu','.jm','.ke','.kh','.kp','.kw','.lb','.lr',
    '.ls','.mm','.mq','.mt','.mz','.ni','.np','.pa','.pg','.py','.qa','.sb','.sv','.sz','.th','.tz',
    '.ve','.ye'
    ]

# the second level domains for those domains above that can be used
# for third level domains
TLDS_COUNTRY_CODE_UNRESTRICTED_LVL2 = [
    '.com.au','.net.au','.org.au','.asn.au','.id.au','.com.bn','.edu.bn','.net.bn','.org.bn','.bt',
    '.com.bt','.edu.bt','.net.bt','.org.bt','.ac.cy','.net.cy','.org.cy','.pro.cy','.name.cy',
    '.ekloges.cy','.tm.cy','.ltd.cy','.biz.cy','.press.cy','.parliament.cy','.com.cy',
    '.centralbank.cy','.com.et','.org.et','.edu.et','.net.et','.name.et','.co.fk','.org.fk',
    '.ac.fk','.nom.fk','.net.fk','.com.gh','.edu.gh','.com.gn','.ac.gn','.org.gn','.net.gn',
    '.com.gu','.net.gu','.org.gu','.edu.gu','.com.jm','.net.jm','.org.jm','.edu.jm','.co.ke',
    '.or.ke','.ne.ke','.go.ke','.ac.ke','.sc.ke','.me.ke','.mobi.ke','.info.ke','.per.kh','.com.kh',
    '.edu.kh','.net.kh','.org.kh','.aca.kp','.com.kp','.edu.kp','.law.kp','.org.kp','.rep.kp',
    '.net.kp','.sca.kp','.com.kw','.ind.kw','.net.kw','.org.kw','.emb.kw','.edu.kw','.com.lb',
    '.edu.lb','.net.lb','.org.lb','.com.lr','.edu.lr','.org.lr','.net.lr','.ac.ls','.co.ls',
    '.net.ls','.nul.ls','.org.ls','.sc.ls','.net.mm','.com.mm','.edu.mm','.org.mm','.edu.mt',
    '.com.mt','.net.mt','.org.mt','.co.mz','.net.mz','.org.mz','.ac.mz','.edu.mz','.gob.ni',
    '.co.ni','.com.ni','.ac.ni','.edu.ni','.org.ni','.nom.ni','.net.ni','.edu.np','.com.np',
    '.org.np','.net.np','.aero.np','.asia.np','.biz.np','.coop.np','.info.np','.jobs.np','.mobi.np',
    '.museum.np','.name.np','.pro.np','.services.np','.travel.np','.net.pa','.com.pa','.ac.pa',
    '.sld.pa','.edu.pa','.org.pa','.abo.pa','.ing.pa','.med.pa','.nom.pa','.com.pg','.net.pg',
    '.ac.pg','.org.pg','.com.py','.coop.py','.edu.py','.org.py','.net.py','.una.py','.com.qa',
    '.edu.qa','.sch.qa','.net.qa','.org.qa','.com.sb','.net.sb','.edu.sv','.com.sv','.org.sv',
    '.red.sv','.co.sz','.ac.sz','.org.sz','.ac.th','.co.th','.or.th','.net.th','.in.th','.co.tz',
    '.ac.tz','.or.tz','.ne.tz','.hotel.tz','.mobi.tz','.tv.tz','.info.tz','.me.tz','.arts.ve',
    '.co.ve','.com.ve','.info.ve','.net.ve','.org.ve','.radio.ve','.web.ve','.com.ye','.co.ye',
    '.ltd.ye','.me.ye','.net.ye','.org.ye','.plc.ye'
]


def replacement_combinations(indices):
    """returns a list of all possible replacement combinations for count
    instances of a character in a string"""
    result = []
    for i in range(1, len(indices) + 1):
        for c in itertools.combinations(indices, i):
            result.append(c)
    return result


def permutate_domain(domain, character, replacements):
    """returns all permutations of character replacements"""
    new_domains = []
    indices = [ i for i, ltr in enumerate(domain) if ltr == character ]
    combinations = replacement_combinations(indices)
    for c in combinations:
        new_domain = domain
        for i in c:
            for r in replacements:
                new_domain = new_domain[:i] + r + new_domain[i + 1:]
        new_domains.append(new_domain)
    return new_domains


def domain_permutations(domain, orig_tld, country_code_tlds=False, original_tlds=False, custom_tlds=[]):
    """returns a list of domains to check"""
    result = []
    domains = [domain, domain.upper()]
    # character replacement
    for c in CHARACTER_LOOK_ALIKES.keys():
        for d in domains:
            count = d.count(c)
            if count > 0:
                permutated_domains = permutate_domain(d, c, CHARACTER_LOOK_ALIKES[c])
                for p in permutated_domains:
                    print(p + orig_tld)


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Finds fudged domains.")
    parser.add_argument("--country-code-tlds", action='store_true', dest="country_code_tld", help="look for unregistered country code TLDs")
    parser.add_argument("--original-tlds", action='store_true', dest="original_tld", help="look for unregistered original TLDs")
    parser.add_argument("--custom-tlds", dest="custom_tld", help="look for custom list of TLDs")
    parser.add_argument("--no-whois", action='store_true', dest="no_whois", help="disable whois queries")
    parser.add_argument("--file", dest="file", help="file containing DNS names to load")
    parser.add_argument("--no-active", action='store_true', dest="no_active", help="disable active checks")
    parser.add_argument("domain", nargs='*', help="domain to fudge")
    args = parser.parse_args()

    # ensure at least one domain was provided
    if not args.file and not args.domain:
        print("[-] must provide a domain as argument or a file containing domains")
        sys.exit(1)

    domains = []
    if args.file:
        if os.path.isfile(args.file):
            with open(args.file, "r") as fd:
                domains = fd.readlines()           
        else:
            print("[-] file not found or permission denied")
            sys.exit(1)
    if args.domain is not None:
        domains.append(args.domain[0])
    
    # for each domain, determine TLDs for domain
    for d in domains:
        domain_parts = d.split(".")
        domain = domain_parts[0]
        tld = "." + ".".join(domain_parts[1:])
        domain_permutations(domain, tld)


if __name__ == "__main__":
    main()