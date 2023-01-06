import ply.lex as lex
import ply.yacc as yacc
from ply.yacc import YaccProduction
from ply.lex import LexToken
import tempfile
import logging

logger = logging.getLogger(__name__)


class SnortRule:
    def __init__(
        self,
        action,
        protocol,
        source_ip,
        source_port,
        direction,
        dest_ip,
        dest_port,
        options_string,
        options_dict,
    ):
        self.action = action
        self.protocol = protocol
        self.source_ip = source_ip
        self.source_port = source_port
        self.direction = direction
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.options_string = options_string
        self.options_dict = options_dict


class Parser:
    def __init__(self, console_logging=False):
        self.lexer = lex.lex(module=self)
        self.parser = yacc.yacc(module=self, outputdir=tempfile.gettempdir())
        self.rules = list()
        self.options = ""
        self.option_string = ""
        self.options_dict = dict()

        if console_logging:
            self._set_logging()

    def parse_rule(self, input_string: str):
        result = self.parser.parse(input_string, lexer=self.lexer)
        return self.rules

    def lex_string(self, input_string: str):
        self.lexer.input(input_string)
        while True:
            tok = self.lexer.token()
            if not tok:
                break
            #if tok.lexpos > 400:
            #    break
            print(tok)

    @staticmethod
    def _set_logging():
        """Set the console logger only if handler(s) aren't already set."""
        if not len(logger.handlers):
            logger.setLevel(logging.DEBUG)
            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG)
            logger.addHandler(ch)

    # List of token names. This is always required
    tokens = [
        "ACTION",
        "PROTOCOL",
        "IP",
        "NUMBER",
        "DIRECTION",
        "ID",
        "OPTION",
        "LPAREN",
        "RPAREN",
        "COLON",
        "SEMICOLON",
        "STRING_ESCAPE",
        "PIPE",
        "DOLLAR",
        "EXCLAMATION",
        "HYPHEN"
    ]

    reserved = {"any": "ANY", "EXTERNAL_NET": "EXTERNAL_NET", "HOME_NET": "HOME_NET"}

    tokens = tokens + list(reserved.values())

    # Regular expression rules for simple tokens
    t_DIRECTION = r"(->|<>)"
    t_LPAREN = r"\("
    t_RPAREN = r"\)"
    t_COLON = r"\:"
    t_STRING_ESCAPE = r"\""
    t_SEMICOLON = r"\;"
    t_PIPE = r"\|"
    t_DOLLAR = r"\$"
    t_EXCLAMATION = r'\!'
    t_HYPHEN = r'\-'

    # A string containing ignored characters (spaces and tabs)
    t_ignore = " \t"

    # Define a rule so we can track line numbers
    @staticmethod
    def t_newline(t: LexToken):
        r"\n+"
        t.lexer.lineno += len(t.value)

    # Error handling rule
    @staticmethod
    def t_error(t: LexToken):
        print("Illegal character '%s'" % t.value[0])
        t.lexer.skip(1)

    @staticmethod
    def t_ACTION(t: LexToken):
        r"(alert|log|pass|activate|dynamic)"
        return t

    @staticmethod
    def t_PROTOCOL(t: LexToken):
        r"(tcp|udp|icmp)"
        return t

    @staticmethod
    def t_OPTION(t: LexToken):
        r"(msg|logto|ttl|tos|ipoption|fragbits|dsize|content|offset|depth|nocase|flags|seq|ack|itype|\
            icode|session|icmp_id|icmp_seq|rpc|resp|content_list|react|distance|within|hash|length|rawbytes|sid|rev)"
        return t

    @staticmethod
    def t_IP(t: LexToken):
        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        return t

    @staticmethod
    def t_NUMBER(t: LexToken):
        r"\d+(\.\d+)?|0x\d+"
        return t

    def t_ID(self, t: LexToken):
        r"[a-zA-Z_][a-zA-Z_0-9.]*"
        t.type = self.reserved.get(t.value, "ID")
        return t

    # Parsing rules
    precedence = (
        (
            "right",
            "ID",
        ),
        (
            "right",
            "OPTION",
        ),
    )

    @staticmethod
    def p_rules(p: YaccProduction):
        """rules : rules rule
                 | rule"""
        if len(p) == 3:
            # multiple rules parsed
            p[0] = p[1] + "\n" + p[2]
        else:
            # single rule parsed
            p[0] = p[1]

    def p_rule(self, p: YaccProduction):
        """rule : ACTION PROTOCOL ip port DIRECTION ip port LPAREN options RPAREN"""
        p[0] = p[1] + p[2] + p[3] + p[4] + p[5] + p[6] + p[7] + p[8] + p[9] + p[10]
        snort_rule = SnortRule(
            action=p[1],
            protocol=p[2],
            source_ip=p[3],
            source_port=p[4],
            direction=p[5],
            dest_ip=p[6],
            dest_port=p[7],
            options_string=p[9],
            options_dict=self.options_dict,
        )
        logger.info(f"Rule matched: {snort_rule.__dict__}")
        self.rules.append(snort_rule)
        self.options = ""
        self.options_dict = dict()

    def p_options(self, p: YaccProduction):
        """options : options option
                   | option"""
        p[0] = self.options

    def p_option(self, p: YaccProduction):
        # matches an option specification, format can change depending on option
        """option : OPTION COLON STRING_ESCAPE expression STRING_ESCAPE SEMICOLON
                  | OPTION COLON NUMBER SEMICOLON
                  | OPTION COLON EXCLAMATION STRING_ESCAPE expression STRING_ESCAPE SEMICOLON"""
        
        if len(p) == 7:
            #content option can have an ! before the string_escape
            p[0] = p[1] + p[2] + p[3] + p[4] + p[5] + p[6]
            self.options += p[0]
            self.options_dict.update({p[1]: p[5]})
            self.option_string = ""
        if len(p) == 5:
            p[0] = p[1] + p[2] + p[3] + p[4]
            self.options += p[0]
            self.options_dict.update({p[1]: p[3]})
            self.option_string = ""
        else:
            p[0] = p[1] + p[2] + p[3] + p[4] + p[5] + p[6]
            self.options += p[0]
            self.options_dict.update({p[1]: p[4]})
            self.option_string = ""

    def p_expression(self, p: YaccProduction):
        """expression : expression term
                      | term"""
        p[0] = self.option_string

    def p_term(self, p: YaccProduction):
        # matches all the text inside of "" for an option
        """term : ID
                | OPTION
                | PIPE
                | NUMBER
                | DOLLAR
                | COLON
                | HYPHEN"""
        p[0] = p[1]
        self.option_string += p[0]

    @staticmethod
    def p_ip(p: YaccProduction):
        """ip : IP
              | ANY
              | DOLLAR HOME_NET
              | DOLLAR EXTERNAL_NET"""
        if len(p) == 3:
            p[0] = p[1] + p[2]
        else:
            p[0] = p[1]

    @staticmethod
    def p_port(p: YaccProduction):
        """port : NUMBER
                | ANY"""
        p[0] = p[1]

    # Error rule for syntax errors
    def p_error(self, p: YaccProduction):
        message = (
            "Unknown text {} for token of type {} on line {} in position {}".format(
                p.value, p.type, p.lineno, p.lexpos
            )
        )
        raise SyntaxError(message, p.lineno, p.lexpos)
