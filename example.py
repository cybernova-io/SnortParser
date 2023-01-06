from snort_parser import Parser


basic_rule = 'alert tcp 192.168.1.0/24 22 -> 192.168.1.1/24 !7:80 (msg:"Test rule banana"; content:"hacking";)'

parser = Parser()
rules = parser.parse_rule(input_string=basic_rule)
for i in rules:
    print(i.__dict__)