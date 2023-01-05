import ply.lex as lex
import ply.yacc as yacc
from ply.yacc import YaccProduction
from ply.lex import LexToken

class Parser:
    # List of token names. This is always required

    def __init__(self):
        self.lexer = lex.lex(module=self)
        self.parser = yacc.yacc(module=self)
        self.rules = list()
        self.options = ""
        self.option_string = ""

    def _add_token(self, token: LexToken):
        print(token)

    def parse_rule(self, input_string: str):
        result = self.parser.parse(input_string, lexer=self.lexer)
        print(result)

    def lex_string(self, input_string: str):
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
    'STRING_ESCAPE',
    'PIPE',
    'ANY',
    'NUMBER'
    ]


    reserved = {
        
    }
    
    tokens = tokens + list(reserved.values())

    # Regular expression rules for simple tokens
    t_IP = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    #t_PORT = r'([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])'
    t_NUMBER = r'[-+]?[0-9]+'
    t_DIRECTION = r'(->|<>)'
    t_LPAREN = r'\('
    t_RPAREN = r'\)'
    t_COLON = r'\:'
    t_STRING_ESCAPE = r'\"'
    t_SEMICOLON = r'\;'
    t_PIPE= r'\|'


    # A string containing ignored characters (spaces and tabs)
    t_ignore  = ' \t'

    # Define a rule so we can track line numbers
    @staticmethod
    def t_newline(t: LexToken):
        r'\n+'
        t.lexer.lineno += len(t.value)

    # Error handling rule
    @staticmethod
    def t_error(t: LexToken):
        print("Illegal character '%s'" % t.value[0])
        t.lexer.skip(1)
    
    @staticmethod
    def t_ACTION(t: LexToken):
        r'(alert|log|pass|activate|dynamic)'
        return t

    @staticmethod
    def t_PROTOCOL(t: LexToken):
        r'(tcp|udp|icmp)'
        return t

    @staticmethod
    def t_OPTION(t: LexToken):
        r'(msg|logto|ttl|tos|ipoption|fragbits|dsize|content|offset\
        |depth|nocase|flags|seq|ack|itype|icode|session|icmp_id|\
        icmp_seq|rpc|resp|content_list|react|distance|within|\
        hash|length|rawbytes|sid|rev    )'
        return t
    
    def t_PORT(self, t: LexToken):
        r'([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])'
        if self.lexer.lexpos < 30:
            return t
        t.type = 'NUMBER'
        return t

    @staticmethod
    def t_ANY(t: LexToken):
        r'any'
        return t
    
    def t_ID(self, t: LexToken):
        r'[a-zA-Z_][a-zA-Z_0-9.]*' 
        t.type = self.reserved.get(t.value, 'ID')
        return t


    # Parsing rules
    precedence = (
        ('right', 'ID', ),
        ('right', 'OPTION',)
    )

    @staticmethod
    def p_rules(p: YaccProduction):
        '''rules : rules rule
                 | rule'''
        
        p[0] = p[1]
        
    
    def p_rule(self, p: YaccProduction):
        '''rule : ACTION PROTOCOL ip port DIRECTION ip port LPAREN options RPAREN'''
        p[0] = p[1] + p[2] + p[3] + p[4] + p[5] + p[6] + p[7] + p[8] + p[9] + p[10]
        
        self.options = "" 
    
    def p_options(self, p: YaccProduction):
        '''options : options option
                   | option'''
        p[0] = self.options
        
    def p_option(self, p: YaccProduction):
        #matches an option specification, format can change depending on option
        '''option : OPTION COLON STRING_ESCAPE expression STRING_ESCAPE SEMICOLON
                  | OPTION COLON NUMBER SEMICOLON
                  | OPTION COLON PORT SEMICOLON'''
        if len(p) == 5:
            p[0] = p[1] + p[2] + p[3] + p[4]
            self.options += p[0]
            self.option_string = ""
        else:
            p[0] = p[1] + p[2] + p[3] + p[4] + p[5] + p[6]
            self.options += p[0]
            self.option_string = ""
    
    def p_expression(self, p : YaccProduction):
        '''expression : expression term
                      | term'''
        p[0] = self.option_string
        
    
    def p_term(self, p: YaccProduction):
        #matches all the text inside of "" for an option
        '''term : ID
                | OPTION
                | PIPE
                | PORT
                | NUMBER'''
        p[0] = p[1]
        self.option_string += p[0]

    @staticmethod
    def p_ip(p: YaccProduction):
        '''ip : IP
              | ANY'''
        p[0] = p[1]

    @staticmethod
    def p_port(p: YaccProduction):
        '''port : PORT
                | ANY'''
        p[0] = p[1]

    # Error rule for syntax errors
    def p_error(self, p: YaccProduction):
        message = 'Unknown text {} for token of type {} on line {} in position {}'.format(p.value, p.type, p.lineno, p.lexpos)
        raise SyntaxError(message, p.lineno, p.lexpos)


basic_rule = 'alert tcp 192.168.1.0 22 -> 192.168.1.1 80 (msg:"Test rule banana lol idk whats going on"; content:"hacking";)'
med_rule = 'alert tcp any any <> any 443 (msg:"APT.Backdoor.MSIL.SUNBURST"; content:"|16 03|"; \
    depth:2; content:"|55 04 03|"; distance:0; content:"digitalcollege.org"; within:50; sid:77600846; rev:1;)'
parser = Parser()
parser.parse_rule(input_string=med_rule)
#parser.lex_string(input_string=med_rule)

