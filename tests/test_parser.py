import pytest
from SRParser import SnortParser
from SRParser import SnortRule

@pytest.fixture()
def parser():
    parser = SnortParser()
    return parser

@pytest.fixture()
def parsed_rule(parser: SnortParser):
    test_rule = '''alert tcp $EXTERNAL_NET any -> $HOME_NET 20034 (msg:"BACKDOOR NetBus Pro 2.0 connection request"; flow:to_server,established; content:"BN|20 00 02 00|"; depth:6; content:"|05 00|"; offset:8; depth:2; flowbits:set,backdoor.netbus_2.connect; flowbits:noalert; classtype:misc-activity; sid:3009; rev:1;)'''
    rules = parser.parse_rules(test_rule)
    return rules[0]

def test_rule_action(parsed_rule):
    assert parsed_rule.action == 'alert'

def test_rule_protocol(parsed_rule):
    assert parsed_rule.protocol == 'tcp'

def test_rule_source_ip(parsed_rule):
    assert parsed_rule.source_ip == '$EXTERNAL_NET'

def test_rule_ports(parsed_rule):
    assert parsed_rule.source_port == 'any'

def test_rule_direction(parsed_rule):
    assert parsed_rule.direction == '->'

def test_rule_dest_ip(parsed_rule):
    assert parsed_rule.dest_ip == '$HOME_NET'

def test_rule_dest_port(parsed_rule):
    assert parsed_rule.dest_port == '20034'

def test_rule_body_options(parsed_rule):
    test_list = [{'msg': '"BACKDOOR NetBus Pro 2.0 connection request"'}, {'flow': 'to_server,established'}, {'content': '"BN|20 00 02 00|"'}, {'depth': '6'}, {'content': '"|05 00|"'}, {'offset': '8'}, {'depth': '2'}, {'flowbits': 'set,backdoor.netbus_2.connect'}, {'flowbits': 'noalert'}, {'classtype': 'misc-activity'}, {'sid': '3009'}, {'rev': '1'}]
    for idx, item in enumerate(parsed_rule.body_options):
        assert item == test_list[idx]
    
