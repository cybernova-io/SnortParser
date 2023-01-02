import ply.lex as lex
import ply.yacc as yacc


class Parser:
    # List of token names. This is always required

    def __init__(self):
        self.lexer = lex.lex(module=self)
        self.parser = yacc.yacc(module=self)

    def _add_token(self, token):
        print(token)

    def parse_rule(self, input_string):
        self.lexer.input(input_string)
        while True:
            tok = self.lexer.token()
            if not tok:
                break
            print(tok)

    tokens = [
    'ACTION',
    'PROTOCOL',
    'IP',
    'PORT',
    'DIRECTION',
    'ID',
    'OPTIONS',
    'LPAREN',
    'RPAREN',
    'COLON',
    'SEMICOLON',
    'STRING_ESCAPE'
    ]

    reserved = {
        'msg': 'MSG',
        'logto': 'LOGTO',
        'ttl': 'TTL',
        'tos': 'TOS',
        'ipoption': 'IPOPTION',
        'fragbits': 'FRAGBITS',
        'dsize': 'DSIZE',
        'content': 'CONTENT',
        'offset': 'OFFSET',
        'depth': 'DEPTH',
        'nocase': 'NOCASE',
        'flags': 'FLAGS',
        'seq': 'SEQ',
        'ack': 'ACK',
        'itype': 'ITYPE',
        'icode': 'ICODE',
        'session': 'SESSION',
        'icmp_id': 'ICMP_ID',
        'icmp_seq': 'ICMP_SEQ',
        'ipoption': 'IPOPTION',
        'rpc': 'RPC',
        'resp': 'RESP',
        'content-list': 'CONTENT_LIST',
        'react': 'REACT'
    }

    tokens = tokens + list(reserved.values())

    # Regular expression rules for simple tokens
    t_IP = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    t_PORT = r'(\d+)'
    t_DIRECTION = r'(->|<>)'
    t_LPAREN = r'\('
    t_RPAREN = r'\)'
    t_COLON = r'\:'
    t_STRING_ESCAPE = r'\"'
    t_SEMICOLON = r'\;'


    # A string containing ignored characters (spaces and tabs)
    t_ignore  = ' \t'

    # Define a rule so we can track line numbers
    @staticmethod
    def t_newline(t):
        r'\n+'
        t.lexer.lineno += len(t.value)

    # Error handling rule
    @staticmethod
    def t_error(t):
        print("Illegal character '%s'" % t.value[0])
        t.lexer.skip(1)
    
    def t_ACTION(self, t):
        r'(alert|log|pass|activate|dynamic)'
        return t
    
    def t_PROTOCOL(self, t):
        r'(tcp|udp|icmp)'
        return t

    def t_ID(self, t):
        r'[a-zA-Z_][a-zA-Z_0-9.]*' 
        t.type = self.reserved.get(t.value, 'ID')
        return t

    # Parsing rules

    @staticmethod
    def p_rules(p):
        '''rules : rules rule
                 | rule'''

    
    def p_rule(self, p):
        '''rule : ACTION PROTOCOL IP PORT DIRECTION IP PORT LPAREN OPTIONS RPAREN'''
        print(p[0])

data = 'alert tcp 192.168.1.0 22 -> 192.168.1.1 80 (msg:"Test rule"; content:"Test content")'
idk = Parser()
idk.parse_rule(input_string=data)

