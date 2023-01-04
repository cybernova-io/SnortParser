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
            result = self.parser.parse(input_string)
            if not input_string:
                break
            print(result)

    def lex_string(self, input_string):
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
    'OPTION',
    'LPAREN',
    'RPAREN',
    'COLON',
    'SEMICOLON',
    'STRING_ESCAPE'
    ]


    reserved = {

    }
    #reserved = {
    #    'msg': 'MSG',
    #    'logto': 'LOGTO',
    #    'ttl': 'TTL',
    #    'tos': 'TOS',
    #    'ipoption': 'IPOPTION',
    ##    'fragbits': 'FRAGBITS',
    ##    'dsize': 'DSIZE',
    #    'content': 'CONTENT',
    #    'offset': 'OFFSET',
    #    'depth': 'DEPTH',
    #    'nocase': 'NOCASE',
    #    'flags': 'FLAGS',
    #    'seq': 'SEQ',
    #    'ack': 'ACK',
    #    'itype': 'ITYPE',
    #    'icode': 'ICODE',
    #    'session': 'SESSION',
    #    'icmp_id': 'ICMP_ID',
    #    'icmp_seq': 'ICMP_SEQ',
    #    'ipoption': 'IPOPTION',
    #    'rpc': 'RPC',
    #    'resp': 'RESP',
    #    'content_list': 'CONTENT_LIST',
    #    'react': 'REACT'
    #}

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

    def t_OPTION(self, t):
        r'(msg|logto|ttl|tos|ipoption|fragbits|dsize|content|offset|depth|nocase|flags|seq|ack|itype|icode|session|icmp_id|icmp_seq|rpc|resp|content_list|react)'
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
        
    @staticmethod
    def p_rule(p):
        '''rule : ACTION PROTOCOL IP PORT DIRECTION IP PORT LPAREN options RPAREN'''
        

    @staticmethod
    def p_options(p):
        '''options : options option
                   | option'''
        

    @staticmethod
    def p_option(p):
        '''option :  OPTION COLON STRING_ESCAPE expression STRING_ESCAPE SEMICOLON'''
        p[0] = p[1] + p[2] + p[3] + p[4] + p[5] + p[6]
        print('OPTION:', p[0])

    @staticmethod
    def p_expression(p):
        '''expression : expression term
                      | term'''
        p[0] = p[1]
    
    @staticmethod
    def p_term(p):
        '''term : ID'''
        p[0] = p[1]
        print('TERM:', p[0])


    #@staticmethod
    #def p_term(p):
    #    '''term : MSG
    #            | LOGTO
    #            | TTL
    #            | TOS
    #            | IPOPTION
    #            | FRAGBITS
    #            | DSIZE
    #            | CONTENT
    #            | OFFSET
    #            | DEPTH
    #            | NOCASE
    #            | FLAGS
    #            | SEQ
    #            | ACK
    #            | ITYPE
    ###            | ICODE
    #            | SESSION
    #            | ICMP_ID
    #            | ICMP_SEQ
    #            | RPC
    #            | RESP
    #            | CONTENT_LIST
    #            | REACT'''
    #    
    
    # Error rule for syntax errors
    def p_error(self, p):
        message = 'Unknown text {} for token of type {} on line {}'.format(p.value, p.type, p.lineno)
        raise TypeError(message, p.lineno, p.lexpos)

#data = 'alert tcp 192.168.1.0 22 -> 192.168.1.1 80 (msg:"Test rule"; content:"Test content")'
data = 'alert tcp 192.168.1.0 22 -> 192.168.1.1 80 (msg:"Test rule";)'
parser = Parser()
parser.parse_rule(input_string=data)
#parser.lex_string(input_string=data)

