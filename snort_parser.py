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
        body_string,
        body_options,
    ):
        self.action = action
        self.protocol = protocol
        self.source_ip = source_ip
        self.source_port = source_port
        self.direction = direction
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.body_string = body_string
        self.body_options = body_options


class Parser:
    def __init__(self, console_logging=False):
        self.lexer = lex.lex(module=self)
        self.parser = yacc.yacc(module=self, outputdir=tempfile.gettempdir())
        self.rules = list()
        self.options = ""
        self.body_string = ""
        self.body_options = list()

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
        "HYPHEN",
        "DOT",
        "SLASH",
        "BSLASH",
        "EQUALS"
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
    t_PIPE = r'\|'
    t_DOLLAR = r'\$'
    t_EXCLAMATION = r'!'
    t_HYPHEN = r'\-'
    t_DOT = r'\.'
    t_SLASH = r'\/'
    t_EQUALS = r'\='
    t_BSLASH = r'\\'

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
        r"(alert|block|drop|log|pass|react|reject|rewrite)"
        return t

    @staticmethod
    def t_PROTOCOL(t: LexToken):
        r"(ip|tcp|udp|icmp)"
        return t

    @staticmethod
    def t_OPTION(t: LexToken):
        r"(msg|reference|gid|sid|rev|classtype|priority|metadata|service|rem|file_meta|\
            |content|bufferlen|isdataat|dsize|pcre|regex|pkt_data|raw_data|file_data|\
            |js_data|base64_decode|base64_data|byte_extract|byte_test|byte_math|ber_data|\
            |ber_skip|ssl_state|ssl_version|dce_iface|dce_opnum|dce_stub_data|sip_method|\
            |sip_method|sip_header|sip_body|sip_stat_code|sd_pattern|asn1|cvs|md5|sha256|\
            |sha512|gtp_info|gtp_type|gtp_version|dnp3_func|dnp3_ind|dnp3_obj|dnp3_data|\
            |cip_attribute|cip_class|cip_conn_path_class|cip_instance|cip_req|cip_rsp|\
            |cip_service|cip_status|enip_command|enip_req|enip_rsp|iec104_apci_type|\
            |iec104_asdu_func|modbus_data|modbus_func|modbus_unit|s7commplus_content|\
            |s7commplus_func|s7commplus_opcode|fragoffset|ttl|tos|id|ipopts|fragbits|\
            |ip_proto|flags|flow|flowbits|file_type|seq|ack|window|itype|icode|icmp_id|\
            |icmp_seq|rpc|stream_reassemble|stream_size|detection_filter|replace|tag|\
            |offset|depth|within|distance|filename)"
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
        """rule : ACTION PROTOCOL ip port DIRECTION ip port LPAREN body RPAREN"""
        p[0] = p[1] + p[2] + p[3] + p[4] + p[5] + p[6] + p[7] + p[8] + p[9] + p[10]
        snort_rule = SnortRule(
            action=p[1],
            protocol=p[2],
            source_ip=p[3],
            source_port=p[4],
            direction=p[5],
            dest_ip=p[6],
            dest_port=p[7],
            body_string=p[9],
            body_options=self.body_options,
        )
        
        logger.info(f"Rule matched: {snort_rule.__dict__}")
        self.rules.append(snort_rule)
        self.options = ""
        self.body_string = ""
        self.body_options = list()

    def p_body(self, p: YaccProduction):
        """body : body option
                | option"""
        p[0] = self.options
        

    def p_option(self, p: YaccProduction):
        """option : OPTION COLON expression SEMICOLON"""
        
        p[0] = p[1] + p[2] + p[3] + p[4]
        option_kvp = {p[1]: p[3]}
        self.body_options.append(option_kvp)
        self.body_string = ""
        self.options += p[0]

    def p_expression(self, p: YaccProduction):
        """expression : expression term
                      | term"""
        p[0] = self.body_string
        

    def p_term(self, p: YaccProduction):
        # matches all the text inside of "" for an option
        """term : ID
                | OPTION
                | PIPE
                | NUMBER
                | DOLLAR
                | COLON
                | HYPHEN
                | DOT
                | SLASH
                | EQUALS
                | BSLASH
                | STRING_ESCAPE
                | EXCLAMATION
                | LPAREN
                | RPAREN"""
        p[0] = p[1]
        self.body_string += p[0]
        

    @staticmethod
    def p_ip(p: YaccProduction):
        """ip : IP
              | IP SLASH NUMBER
              | ANY
              | DOLLAR HOME_NET
              | DOLLAR EXTERNAL_NET"""
        
        if len(p) == 4:
            p[0] = p[1] + p[2] + p[3]
            return p[0]
        if len(p) == 3:
            p[0] = p[1] + p[2]
            return p[0]
        p[0] = p[1]

    @staticmethod
    def p_port(p: YaccProduction):
        """port : NUMBER
                | ANY
                | NUMBER COLON NUMBER
                | COLON NUMBER
                | NUMBER COLON
                | EXCLAMATION NUMBER
                | EXCLAMATION NUMBER COLON NUMBER
                | EXCLAMATION COLON NUMBER
                | EXCLAMATION NUMBER COLON"""
        if len(p) == 5:
            p[0] = p[1] + p[2] + p[3] + p[4]
            return p[0]
        if len(p) == 4:
            p[0] = p[1] + p[2] + p[3]
            return p[0]
        if len(p) == 3:
            p[0] = p[1] + p[2]
            return p[0]
        p[0] = p[1]

    # Error rule for syntax errors
    def p_error(self, p: YaccProduction):
        message = (
            "Unknown text {} for token of type {} on line {} in position {}".format(
                p.value, p.type, p.lineno, p.lexpos
            )
        )
        raise SyntaxError(message, p.lineno, p.lexpos)


basic_rule = 'alert tcp 192.168.1.0/24 22 -> 192.168.1.1/24 80 (msg:"Test rule banana lol idk whats going on"; content:"hacking";)'

parser = Parser()
rules = parser.parse_rule(input_string=basic_rule)
#parser.lex_string(input_string=basic_rule)
for i in rules:
    print(i.__dict__)