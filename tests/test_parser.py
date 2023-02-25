import pytest
from SRParser import SnortParser
import re

@pytest.fixture()
def parsed_rule():
    rule = """alert tcp $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any ( msg:"INDICATOR-COMPROMISE file copied ok"; flow:to_client,established; file_data; content:"1 file|28|s|29| copied",fast_pattern,nocase; metadata:policy max-detect-ips drop,ruleset community; service:http; reference:bugtraq,1806; reference:cve,2000-0884; classtype:bad-unknown; sid:497; rev:21; )"""
    parser = SnortParser(skip_error_rules=False)
    rules = parser.parse_rules(rule)
    return rules[0]

def test_rule_action(parsed_rule):
    assert parsed_rule.action == 'alert'

def test_rule_body_options(parsed_rule):
    test_list = [{'msg': '"INDICATOR-COMPROMISE file copied ok"'}, {'flow': 'to_client,established'}, {'file_data': ';'}, {'content': '"1 file|28|s|29| copied",fast_pattern,nocase'}, {'metadata': 'policy max-detect-ips drop,ruleset community'}, {'service': 'http'}, {'reference': 'bugtraq,1806'}, {'reference': 'cve,2000-0884'}, {'classtype': 'bad-unknown'}, {'sid': '497'}, {'rev': '21'}]
    for idx, item in enumerate(parsed_rule.body_options):
        assert item == test_list[idx]

def test_vs_community_ruleset():
    contents = open('snort3-community.txt').readlines()
    for rule in contents:
        parser = SnortParser(skip_error_rules=False)
        parsed_rule = parser.parse_rules(rule)[0]
        assert re.sub('\s', '', parsed_rule.raw_text) == re.sub('\s', '', rule)
               
def test_vs_community_ruleset_strict():
    contents = open('snort3-community.txt').readlines()
    for rule in contents:
        parser = SnortParser(skip_error_rules=False)
        parsed_rule = parser.parse_rules(rule)[0]
        assert parsed_rule.raw_text.strip() == rule.strip()
              
   
    
