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
        body_options,
        source_ip=None,
        source_port=None,
        direction=None,
        dest_ip=None,
        dest_port=None,
    ):
        """Class representing a snort rule. Service rules use less parameters than normal rules."""
        self.action = action
        self.protocol = protocol
        self.source_ip = source_ip
        self.source_port = source_port
        self.direction = direction
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.body_options = body_options
        self.raw_text = ""

        if source_ip == None:
            self.service_rule = True
        else:
            self.service_rule = False

    def rebuild_rule(self):
        """Take a SnortRule object and rebuild the raw text version."""
        if self.service_rule == False:
            rule = (
                self.action
                + " "
                + self.protocol
                + " "
                + self.source_ip
                + " "
                + self.source_port
                + " "
                + self.direction
                + " "
                + self.dest_ip
                + " "
                + self.dest_port
                + " ( "
            )
        if self.service_rule == True:
            rule = self.action + " " + self.protocol + " ( "

        for option in self.body_options:
            rule += str(*option)
            opt = option.pop(*option)
            if opt == " ":
                rule += "; "
            else:
                rule += ":"
                rule += opt
                rule += ";" + " "
        rule = rule[:-1]
        rule += " )"
        self.raw_text = rule
        return self.raw_text


class SnortParser:
    def __init__(self, console_logging=False, skip_error_rules=True):
        """
        Initialize parser.
        Optional args -
        console_logging: print logging information to console
        skip_error_rules: whether to stop if an error is encountered, errors are saved to error_log if true
        """
        self.lexer = lex.lex(module=self, debug=False)
        self.parser = yacc.yacc(
            module=self, debug=False, outputdir=tempfile.gettempdir()
        )
        self.options = ""
        self.body_string = ""
        self.body_options = list()

        self.rules = list()

        self.error_log = list()
        self.skip_error_rules = skip_error_rules

        if console_logging:
            self._set_logging()

    def parse_rules(self, input_string: str):
        """Parse an input string expected to contain snort rules."""
        self.parser.parse(input_string, lexer=self.lexer)
        return self.rules

    def rebuild_rule(
        self,
        action: str,
        protocol: str,
        source_ip: str,
        source_port: str,
        direction: str,
        dest_ip: str,
        dest_port: str,
        body_options: list,
    ):
        """Take components of a snort rule and rebuild it into the raw text."""
        rule = ""
        rule = (
            action
            + " "
            + protocol
            + " "
            + source_ip
            + " "
            + source_port
            + " "
            + direction
            + " "
            + dest_ip
            + " "
            + dest_port
            + " ("
        )
        for option in body_options:
            rule += str(*option)
            rule += ":"
            rule += option.pop(*option)
            rule += ";" + " "
        rule = rule[:-1]
        rule += ")"
        return rule

    def _lex_string(self, input_string: str):
        self.lexer.input(input_string)
        while True:
            tok = self.lexer.token()
            if not tok:
                break
            print(tok)

    @staticmethod
    def __set_logging():
        """Set the console logger only if handler(s) aren't already set."""
        if not len(logger.handlers):
            logger.setLevel(logging.DEBUG)
            log = logging.StreamHandler()
            log.setLevel(logging.DEBUG)
            logger.addHandler(log)

    # List of token names. This is always required
    tokens = [
        "ACTION",
        "PROTOCOL",
        "IP",
        "NUMBER",
        "DIRECTION",
        "ID",
        "OPTION",
        "SERVICE",
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
        "EQUALS",
        "LBRACK",
        "RBRACK",
        "COMMA",
        "LBRACE",
        "RBRACE",
        "GREATERTHAN",
        "LESSTHAN",
        "STAR",
        "CARET",
        "AND",
        "QUESTION",
        "PLUS",
        "MODULO",
        "SPACE",
        "AT",
        "POUND",
        "TILDE",
        "APOSTROPHE",
        "BACKTICK",
    ]

    reserved = {
        "any": "ANY",
        "EXTERNAL_NET": "EXTERNAL_NET",
        "HOME_NET": "HOME_NET",
        "HTTP_PORTS": "HTTP_PORTS",
        "SMTP_SERVERS": "SMTP_SERVERS",
        "TELNET_SERVERS": "TELNET_SERVERS",
        "HTTP_SERVERS": "HTTP_SERVERS",
        "HTTP_PORTS": "HTTP_PORTS",
        "FTP_PORTS": "FTP_PORTS",
        "FILE_DATA_PORTS": "FILE_DATA_PORTS",
        "SQL_SERVERS": "SQL_SERVERS",
        "ORACLE_PORTS": "ORACLE_PORTS",
        "SIP_SERVERS": "SIP_SERVERS",
        "SSH_PORTS": "SSH_PORTS",
        "SIP_PORTS": "SIP_PORTS",
    }

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
    t_EXCLAMATION = r"!"
    t_HYPHEN = r"\-"
    t_DOT = r"\."
    t_SLASH = r"\/"
    t_EQUALS = r"\="
    t_BSLASH = r"\\"
    t_LBRACK = r"\["
    t_RBRACK = r"\]"
    t_COMMA = r"\,"
    t_LBRACE = r"\{"
    t_RBRACE = r"\}"
    t_GREATERTHAN = r"\>"
    t_LESSTHAN = r"\<"
    t_STAR = r"\*"
    t_CARET = r"\^"
    t_AND = r"\&"
    t_QUESTION = r"\?"
    t_PLUS = r"\+"
    t_MODULO = r"\%"
    t_SPACE = r"\ "
    t_POUND = r"\#"
    t_AT = r"\@"
    t_BACKTICK = r"\`"
    t_APOSTROPHE = r"\'"
    t_TILDE = r"\~"

    # A string containing ignored characters (tabs)
    t_ignore = "\t"

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
            |ip_proto|flags|flowbits|flow|file_type|seq|ack|window|itype|icode|icmp_id|\
            |icmp_seq|rpc|stream_reassemble|stream_size|detection_filter|replace|tag|\
            |offset|depth|within|distance|filename|charset|nocase|fast_pattern|protected_content|\
            |ip_proto|byte_jump|uricontent|http_uri|raw_http_uri|http_client_body|http_raw_body|\
            |http_cookie|http_raw_cookie|http_method|http_raw_header|http_header|http_raw_uri|\
            |http_stat_code|http_stat_msg)"
        return t

    @staticmethod
    def t_SERVICE(t: LexToken):
        r"(ssl|http)"
        return t

    @staticmethod
    def t_PROTOCOL(t: LexToken):
        r"(ip|tcp|udp|icmp)"
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
        """rule : ACTION SPACE PROTOCOL SPACE ip SPACE port SPACE DIRECTION SPACE ip SPACE port SPACE LPAREN body RPAREN
        | ACTION SPACE PROTOCOL SPACE ip SPACE port SPACE DIRECTION SPACE ip SPACE port SPACE LPAREN SPACE body RPAREN
        | ACTION SPACE PROTOCOL SPACE ip SPACE port SPACE DIRECTION SPACE ip SPACE port SPACE LPAREN body SPACE RPAREN
        | ACTION SPACE PROTOCOL SPACE ip SPACE port SPACE DIRECTION SPACE ip SPACE port SPACE LPAREN SPACE body SPACE RPAREN
        | ACTION SPACE SERVICE SPACE LPAREN SPACE body SPACE RPAREN
        | ACTION SPACE SERVICE SPACE LPAREN SPACE body RPAREN"""
        if len(p) == 20:
            p[0] = (
                p[1] + p[3] + p[5] + p[7] + p[9] + p[11] + p[13] + p[15] + p[17] + p[19]
            )
            snort_rule = SnortRule(
                action=p[1],
                protocol=p[3],
                source_ip=p[5],
                source_port=p[7],
                direction=p[9],
                dest_ip=p[11],
                dest_port=p[13],
                body_options=self.body_options,
            )

            logger.info(f"Rule matched: {snort_rule.__dict__}")
            self.rules.append(snort_rule)
            self.options = ""
            self.body_options = list()
        if len(p) == 19:
            p[0] = (
                p[1] + p[3] + p[5] + p[7] + p[9] + p[11] + p[13] + p[15] + p[17] + p[18]
            )
            snort_rule = SnortRule(
                action=p[1],
                protocol=p[3],
                source_ip=p[5],
                source_port=p[7],
                direction=p[9],
                dest_ip=p[11],
                dest_port=p[13],
                body_options=self.body_options,
            )

            logger.info(f"Rule matched: {snort_rule.__dict__}")
            self.rules.append(snort_rule)
            self.options = ""
            self.body_options = list()
        if len(p) == 18:
            p[0] = p[1] + p[2] + p[3] + p[4] + p[5] + p[6] + p[7] + p[8] + p[9] + p[10]
            snort_rule = SnortRule(
                action=p[1],
                protocol=p[3],
                source_ip=p[5],
                source_port=p[7],
                direction=p[9],
                dest_ip=p[11],
                dest_port=p[13],
                body_options=self.body_options,
            )

            logger.info(f"Rule matched: {snort_rule.__dict__}")
            self.rules.append(snort_rule)
            self.options = ""
            self.body_options = list()

        if len(p) == 10:
            p[0] = p[1] + p[3] + p[5] + p[7] + p[9]
            snort_rule = SnortRule(
                action=p[1],
                protocol=p[3],
                body_options=self.body_options,
            )

            logger.info(f"Rule matched: {snort_rule.__dict__}")
            self.rules.append(snort_rule)
            self.options = ""
            self.body_options = list()

        if len(p) == 9:
            p[0] = p[1] + p[3] + p[5] + p[7] + p[8]
            snort_rule = SnortRule(
                action=p[1],
                protocol=p[3],
                body_options=self.body_options,
            )

            logger.info(f"Rule matched: {snort_rule.__dict__}")
            self.rules.append(snort_rule)
            self.options = ""
            self.body_options = list()

    def p_body(self, p: YaccProduction):
        """body : body option
        | option"""
        p[0] = self.options

    def p_option(self, p: YaccProduction):
        """option : OPTION COLON expression SEMICOLON
        | OPTION SEMICOLON
        | OPTION COLON expression SEMICOLON SPACE
        | OPTION SEMICOLON SPACE"""
        if len(p) == 6:
            p[0] = p[1] + p[2] + p[3] + p[4]
            option_kvp = {p[1]: p[3]}
            self.body_options.append(option_kvp)
            self.body_string = ""
            self.options += p[0]
        if len(p) == 5:
            p[0] = p[1] + p[2] + p[3] + p[4]
            option_kvp = {p[1]: p[3]}
            self.body_options.append(option_kvp)
            self.body_string = ""
            self.options += p[0]
        if len(p) == 4:
            p[0] = p[1] + p[2] + p[3]
            option_kvp = {p[1]: p[3]}
            self.body_options.append(option_kvp)
            self.body_string = ""
            self.options += p[0]
        if len(p) == 3:
            p[0] = p[1] + p[2]
            option_kvp = {p[1]: p[2]}
            self.body_options.append(option_kvp)
            self.body_string = ""
            self.options += p[0]

    def p_expression(self, p: YaccProduction):
        """expression : expression term
        | term"""

        p[0] = self.body_string

    def p_term(self, p: YaccProduction):
        # matches all the text between : ; for an option
        """term : ID
        | OPTION
        | ACTION
        | SERVICE
        | PROTOCOL
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
        | RPAREN
        | COMMA
        | LBRACK
        | RBRACK
        | LBRACE
        | RBRACE
        | GREATERTHAN
        | LESSTHAN
        | STAR
        | CARET
        | AND
        | AT
        | POUND
        | TILDE
        | QUESTION
        | PLUS
        | MODULO
        | BSLASH SEMICOLON
        | BACKTICK
        | APOSTROPHE
        | SPACE
        | DIRECTION
        | IP"""
        if len(p) == 3:
            p[0] = p[1] + p[2]
            self.body_string += p[0]
        else:
            p[0] = p[1]
            self.body_string += p[0]

    @staticmethod
    def p_ip(p: YaccProduction):
        """ip : IP
        | IP SLASH NUMBER
        | ANY
        | DOLLAR HOME_NET
        | DOLLAR EXTERNAL_NET
        | DOLLAR SMTP_SERVERS
        | DOLLAR TELNET_SERVERS
        | DOLLAR HTTP_SERVERS
        | LBRACK list RBRACK
        | DOLLAR SQL_SERVERS
        | DOLLAR SIP_SERVERS"""

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
        | EXCLAMATION NUMBER COLON
        | LBRACK list RBRACK
        | DOLLAR HTTP_PORTS
        | DOLLAR FILE_DATA_PORTS
        | DOLLAR FTP_PORTS
        | DOLLAR ORACLE_PORTS
        | DOLLAR SSH_PORTS
        | DOLLAR SIP_PORTS"""
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

    @staticmethod
    def p_list(p: YaccProduction):
        """list : list item
        | item"""
        if len(p) == 3:
            p[0] = p[1] + p[2]
            return p[0]
        p[0] = p[1]

    @staticmethod
    def p_item(p: YaccProduction):
        """item : port
        | ip
        | COMMA"""
        p[0] = p[1]

    # Error rule for syntax errors
    def p_error(self, p: YaccProduction):
        message = "Unknown character {} for token of type {} on line {} in position {}".format(
            p.value, p.type, p.lineno, p.lexpos
        )

        if self.skip_error_rules == True:
            self.error_log.append(message)
            p.lineno += 1
            p.lexpos = 0
        if self.skip_error_rules == False:
            raise SyntaxError(message, p.lineno, p.lexpos)
