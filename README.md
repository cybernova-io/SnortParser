## Intro

Snort rule tokenizer and parser written using PLY. This is my first tokenizer, parser and I may make improvements/changes as time goes on. The focus of this package currently is to allow programmatically working with snort rules, not necessarily detect the minutae of incorrect option combinations.

If you have any suggestions, ideas, or improvements feel free to open an issue. Inspiration drawn from plyara. Thanks to David Beazley for his work on the PLY package.

## Usage

```python
pip install SRParser
```

```python
from SRParser import SnortParser

data = '''
alert tcp $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any ( msg:"INDICATOR-COMPROMISE file copied ok"; flow:to_client,established; file_data; content:"1 file|28|s|29| copied",fast_pattern,nocase; metadata:policy max-detect-ips drop,ruleset community; service:http; reference:bugtraq,1806; reference:cve,2000-0884; classtype:bad-unknown; sid:497; rev:21; )
'''

parser = SnortParser()
my_rules = parser.parse_rules(data)

for rule in my_rules:
    print(rule.__dict__)
```

```
{'action': 'alert', 'protocol': 'tcp', 'source_ip': '$HTTP_SERVERS', 'source_port': '$HTTP_PORTS', 'direction': '->', 'dest_ip': '$EXTERNAL_NET', 'dest_port': 'any', 'body_options': [{'msg': '"INDICATOR-COMPROMISE file copied ok"'}, {'flow': 'to_client,established'}, {'file_data': ';'}, {'content': '"1 file|28|s|29| copied",fast_pattern,nocase'}, {'metadata': 'policy max-detect-ips drop,ruleset 
community'}, {'service': 'http'}, {'reference': 'bugtraq,1806'}, {'reference': 'cve,2000-0884'}, {'classtype': 'bad-unknown'}, {'sid': '497'}, {'rev': '21'}], 'raw_text': 'alert tcp $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any ( msg:"INDICATOR-COMPROMISE file copied ok"; flow:to_client,established; file_data; content:"1 file|28|s|29| copied",fast_pattern,nocase; metadata:policy max-detect-ips 
drop,ruleset community; service:http; reference:bugtraq,1806; reference:cve,2000-0884; classtype:bad-unknown; sid:497; rev:21; )', 'service_rule': False}
```
