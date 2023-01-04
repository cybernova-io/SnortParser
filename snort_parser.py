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
        self.string = ""

    def _add_token(self, token):
        print(token)

    def parse_rule(self, input_string):
        result = self.parser.parse(input_string, lexer=self.lexer)
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
    def t_newline(t: LexToken):
        r'\n+'
        t.lexer.lineno += len(t.value)

    # Error handling rule
    @staticmethod
    def t_error(t: LexToken):
        print("Illegal character '%s'" % t.value[0])
        t.lexer.skip(1)
    
    def t_ACTION(self, t: LexToken):
        r'(alert|log|pass|activate|dynamic)'
        return t
    
    def t_PROTOCOL(self, t: LexToken):
        r'(tcp|udp|icmp)'
        return t

    def t_OPTION(self, t: LexToken):
        r'(msg|logto|ttl|tos|ipoption|fragbits|dsize|content|offset|depth|nocase|flags|seq|ack|itype|icode|session|icmp_id|icmp_seq|rpc|resp|content_list|react)'
        return t

    def t_ID(self, t: LexToken):
        r'[a-zA-Z_][a-zA-Z_0-9.]*' 
        t.type = self.reserved.get(t.value, 'ID')
        return t

    # Parsing rules

    @staticmethod
    def p_rules(p: YaccProduction):
        '''rules : rules rule
                 | rule'''
        
        p[0] = p[1]
        
    @staticmethod
    def p_rule(p: YaccProduction):
        '''rule : ACTION PROTOCOL IP PORT DIRECTION IP PORT LPAREN options RPAREN'''
        p[0] = p[1] + p[2] + p[3] + p[4] + p[5] + p[6] + p[7] + p[8] + p[9] + p[10]

    @staticmethod
    def p_options(p: YaccProduction):
        '''options : options option
                   | option'''
        p[0] = p[1]
        
    @staticmethod
    def p_option(p: YaccProduction):
        '''option :  OPTION COLON STRING_ESCAPE expression STRING_ESCAPE SEMICOLON'''
        p[0] = p[1] + p[2] + p[3] + p[4] + p[5] + p[6]
        #print('OPTION:', p[0])

    
    def p_expression(self, p : YaccProduction):
        '''expression : expression term
                      | term'''
        p[0] = self.string
    
    def p_term(self, p: YaccProduction):
        '''term : term ID
                | ID'''
        if len(p) > 2:
            p[0] = p[2]
            self.string += p[0]
        else:
            p[0] = p[1]
            self.string += p[0]

    # Error rule for syntax errors
    def p_error(self, p):
        message = 'Unknown text {} for token of type {} on line {}'.format(p.value, p.type, p.lineno)
        raise SyntaxError(message, p.lineno, p.lexpos)

#data = 'alert tcp 192.168.1.0 22 -> 192.168.1.1 80 (msg:"Test rule"; content:"Test content";    )'
data = 'alert tcp 192.168.1.0 22 -> 192.168.1.1 80 (msg:"Test rule banana lol idk whats going on";)'
parser = Parser()
parser.parse_rule(input_string=data)
#parser.lex_string(input_string=data)

