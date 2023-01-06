## Intro
Snort rule tokenizer and parser written using PLY. This is my first tokenizer, parser and I may make improvements as time goes on. I plan to test it more but it seems to be roughly working and I will release it so it can be tested more. If you have any suggestions, ideas, or improvements feel free to open an issue. Inspiration drawn from plyara.

## Usage

```python
pip install SRParser
```

```python
from SRParser import SnortParser

parser = SnortParser()

data = '''
alert tcp any any -> any 1080 (msg:"TEST"; content:"hostip"; offset:3; depth:12; flags:A; sid:123;)
'''

my_rules = parser.parse_rules(data)

for i in my_rules:
    print(i.__dict__)
```

```
{'action': 'alert', 'protocol': 'tcp', 'source_ip': 'any', 'source_port': 'any', 'direction': '->', 'dest_ip': 'any', 'dest_port': '1080', 'body_string': 'msg:"TEST";content:"hostip";offset:3;depth:12;flags:A;sid:123;', 'body_options': [{'msg': '"TEST"'}, {'content': '"hostip"'}, {'offset': '3'}, {'depth': '12'}, {'flags': 'A'}, {'sid': '123'}]}
```
