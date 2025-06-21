import re
import sys

TOKEN_SPECIFICATION = [
    ("ENCRYPT",      r"⊗"),
    ("WITH",         r"⊕"),
    ("SEND",         r"→"),
    ("TO",           r"⚡"),
    ("DENY",         r"!"),
    ("NOT_EQUAL",    r"≠"),
    ("ASSIGN",       r"←"),
    ("QUESTION",     r"\?"),
    ("COLON",        r":"),
    ("SEMICOLON",    r";"),
    ("EQUAL",        r"=="),
    ("NOT_EQUAL_EQ", r"!="),
    ("LE",           r"≤"),
    ("GE",           r"≥"),
    ("LT",           r"<"),
    ("GT",           r">"),
    ("PLUS",         r"\+"),
    ("MINUS",        r"-"),
    ("MULT",         r"\*"),
    ("DIV",          r"/"),
    ("AND",          r"&"),
    ("OR",           r"\|"),
    ("XOR",          r"\^"),
    ("NUMBER",       r"\d+(\.\d*)?"),
    ("STRING",       r'"[^"]*"'),
    ("BOOLEAN",      r"\b(true|false)\b"),
    ("IDENTIFIER",   r"[a-zA-Z_][a-zA-Z0-9_]*"),
    ("LPAREN",       r"\("),
    ("RPAREN",       r"\)"),
    ("COMMA",        r","),
    ("NEWLINE",      r"\n"),
    ("SKIP",         r"[ \t]+"),
    ("MISMATCH",     r"."),
]

FUNCTION_TYPES = {"ketamine", "dmt", "arch", "dark", "void"}

class Lexer:
    def __init__(self, code):
        self.code = code
        self.tokens = []
        self.token_regex = re.compile("|".join(f"(?P<{name}>{pattern})" for name, pattern in TOKEN_SPECIFICATION))
        
    def tokenize(self):
        for mo in self.token_regex.finditer(self.code):
            kind = mo.lastgroup
            value = mo.group()
            if kind in ("SKIP", "NEWLINE"):
                continue
            elif kind == "MISMATCH":
                raise RuntimeError(f"Unexpected character: {value}")
            else:
                self.tokens.append((kind, value))
        self.tokens.append(("EOF", "EOF"))
        return self.tokens


# AST Nodes (add FunctionCall node for mythical functions)

class ASTNode:
    pass

class Program(ASTNode):
    def __init__(self, statements):
        self.statements = statements
    def __repr__(self):
        return f"Program({self.statements})"

class EncryptStmt(ASTNode):
    def __init__(self, data, key):
        self.data = data
        self.key = key
    def __repr__(self):
        return f"Encrypt({self.data}, {self.key})"

class SendStmt(ASTNode):
    def __init__(self, data, target):
        self.data = data
        self.target = target
    def __repr__(self):
        return f"Send({self.data}, {self.target})"

class DenyStmt(ASTNode):
    def __init__(self, condition):
        self.condition = condition
    def __repr__(self):
        return f"Deny({self.condition})"

class AssignStmt(ASTNode):
    def __init__(self, identifier, expr):
        self.identifier = identifier
        self.expr = expr
    def __repr__(self):
        return f"Assign({self.identifier}, {self.expr})"

class ConditionalStmt(ASTNode):
    def __init__(self, condition, statements):
        self.condition = condition
        self.statements = statements
    def __repr__(self):
        return f"Conditional({self.condition}, {self.statements})"

class BinaryOp(ASTNode):
    def __init__(self, left, op, right):
        self.left = left
        self.op = op
        self.right = right
    def __repr__(self):
        return f"({self.left} {self.op} {self.right})"

class Literal(ASTNode):
    def __init__(self, value):
        self.value = value
    def __repr__(self):
        return f"Literal({self.value})"

class Identifier(ASTNode):
    def __init__(self, name):
        self.name = name
    def __repr__(self):
        return f"Identifier({self.name})"

class FunctionStmt(ASTNode):
    def __init__(self, func_name, condition, statements):
        self.func_name = func_name
        self.condition = condition  
        self.statements = statements  
    def __repr__(self):
        return f"FunctionStmt({self.func_name}, {self.condition}, {self.statements})"

# New AST node for mythical/custom functions called in expressions
class FunctionCall(ASTNode):
    def __init__(self, func_name, args):
        self.func_name = func_name
        self.args = args
    def __repr__(self):
        return f"FunctionCall({self.func_name}, {self.args})"


# Parser with expression parsing (precedence, parentheses, function calls)

class Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0
        self.current_token = tokens[0]

    def advance(self):
        self.pos += 1
        if self.pos < len(self.tokens):
            self.current_token = self.tokens[self.pos]

    def expect(self, token_type):
        if self.current_token[0] == token_type:
            val = self.current_token[1]
            self.advance()
            return val
        else:
            raise RuntimeError(f"Expected {token_type} but got {self.current_token}")

    def parse(self):
        statements = []
        while self.current_token[0] != "EOF":
            stmt = self.statement()
            statements.append(stmt)
        return Program(statements)

    def statement(self):
        tok_type, tok_val = self.current_token

        if tok_type == "IDENTIFIER" and tok_val.lower() in FUNCTION_TYPES:
            return self.function_stmt()

        if tok_type == "ENCRYPT":
            return self.encrypt_stmt()
        elif tok_type == "SEND":
            return self.send_stmt()
        elif tok_type == "DENY":
            return self.deny_stmt()
        elif tok_type == "IDENTIFIER":
            # Could be assignment or expression statement (but you have only assignments)
            # So, check if next token is ASSIGN:
            next_tok_type = self.tokens[self.pos + 1][0] if (self.pos + 1) < len(self.tokens) else None
            if next_tok_type == "ASSIGN":
                return self.assign_stmt()
            else:
                # Or expression statement? (Not in original spec)
                raise RuntimeError(f"Unexpected IDENTIFIER without assignment: {self.current_token}")
        elif tok_type == "QUESTION":
            return self.conditional_stmt()
        else:
            raise RuntimeError(f"Unexpected token in statement: {self.current_token}")

    def encrypt_stmt(self):
        self.expect("ENCRYPT")
        data = self.expect("IDENTIFIER")
        self.expect("WITH")
        key = self.expect("IDENTIFIER")
        return EncryptStmt(Identifier(data), Identifier(key))

    def send_stmt(self):
        self.expect("SEND")
        tok_type, tok_val = self.current_token
        if tok_type == "IDENTIFIER":
            data = Identifier(tok_val)
            self.advance()
        elif tok_type == "STRING":
            data = Literal(tok_val[1:-1])  
            self.advance()
        else:
            raise RuntimeError(f"Invalid data in send statement: expected IDENTIFIER or STRING but got {self.current_token}")

        self.expect("TO")
        tok_type, tok_val = self.current_token
        if tok_type == "IDENTIFIER":
            target = Identifier(tok_val)
            self.advance()
        elif tok_type == "STRING":
            target = Literal(tok_val[1:-1])  
            self.advance()
        else:
            raise RuntimeError("Invalid target in send statement: expected IDENTIFIER or STRING")

        return SendStmt(data, target)

    def deny_stmt(self):
        self.expect("DENY")
        ident_access = self.expect("IDENTIFIER")  
        if ident_access != "access":
            raise RuntimeError(f"Expected 'access' identifier but got {ident_access}")
        self.expect("NOT_EQUAL")
        ident = self.expect("IDENTIFIER")
        cond = BinaryOp(Identifier("access"), "!=", Identifier(ident))
        return DenyStmt(cond)

    def assign_stmt(self):
        identifier = self.expect("IDENTIFIER")
        self.expect("ASSIGN")
        expr = self.expression()
        return AssignStmt(Identifier(identifier), expr)

    def conditional_stmt(self):
        self.expect("QUESTION")
        condition = self.condition()
        self.expect("COLON")
        first_stmt = self.statement()
        stmts = [first_stmt]
        while self.current_token[0] == "SEMICOLON":
            self.expect("SEMICOLON")
            stmts.append(self.statement())
        return ConditionalStmt(condition, stmts)

    def condition(self):
        left = self.expression()
        tok_type = self.current_token[0]
        if tok_type in ("EQUAL", "NOT_EQUAL_EQ", "NOT_EQUAL", "LT", "GT", "LE", "GE"):
            op = self.current_token[1]
            self.advance()
            right = self.expression()
            return BinaryOp(left, op, right)
        else:
            return left

    # Expression parser with precedence, function calls, parentheses
    def expression(self):
        return self.expr_or()

    def expr_or(self):
        node = self.expr_xor()
        while self.current_token[0] == "OR":
            op = self.current_token[1]
            self.advance()
            right = self.expr_xor()
            node = BinaryOp(node, op, right)
        return node

    def expr_xor(self):
        node = self.expr_and()
        while self.current_token[0] == "XOR":
            op = self.current_token[1]
            self.advance()
            right = self.expr_and()
            node = BinaryOp(node, op, right)
        return node

    def expr_and(self):
        node = self.expr_add_sub()
        while self.current_token[0] == "AND":
            op = self.current_token[1]
            self.advance()
            right = self.expr_add_sub()
            node = BinaryOp(node, op, right)
        return node

    def expr_add_sub(self):
        node = self.expr_mul_div()
        while self.current_token[0] in ("PLUS", "MINUS"):
            op = self.current_token[1]
            self.advance()
            right = self.expr_mul_div()
            node = BinaryOp(node, op, right)
        return node

    def expr_mul_div(self):
        node = self.expr_unary()
        while self.current_token[0] in ("MULT", "DIV"):
            op = self.current_token[1]
            self.advance()
            right = self.expr_unary()
            node = BinaryOp(node, op, right)
        return node

    def expr_unary(self):
        if self.current_token[0] == "MINUS":
            op = self.current_token[1]
            self.advance()
            operand = self.expr_unary()
            return BinaryOp(Literal(0), op, operand)
        else:
            return self.expr_primary()

    def expr_primary(self):
        tok_type, tok_val = self.current_token

        if tok_type == "NUMBER":
            self.advance()
            return Literal(float(tok_val) if '.' in tok_val else int(tok_val))

        elif tok_type == "STRING":
            self.advance()
            return Literal(tok_val[1:-1])

        elif tok_type == "BOOLEAN":
            self.advance()
            return Literal(tok_val == "true")

        elif tok_type == "IDENTIFIER":
            # Could be variable or function call
            self.advance()
            if self.current_token[0] == "LPAREN":
                # Function call
                func_name = tok_val
                self.expect("LPAREN")
                args = []
                if self.current_token[0] != "RPAREN":
                    args.append(self.expression())
                    while self.current_token[0] == "COMMA":
                        self.expect("COMMA")
                        args.append(self.expression())
                self.expect("RPAREN")
                return FunctionCall(func_name, args)
            else:
                return Identifier(tok_val)

        elif tok_type == "LPAREN":
            self.advance()
            node = self.expression()
            self.expect("RPAREN")
            return node

        else:
            raise RuntimeError(f"Unexpected token in expression: {self.current_token}")

    def function_stmt(self):
        func_name = self.current_token[1].lower()
        self.advance()

        self.expect("COLON")

        condition = None
        statements = []

        if self.current_token[0] == "QUESTION":
            self.expect("QUESTION")
            condition = self.condition()
            self.expect("COLON")

        if self.current_token[0] == "EOF":
            return FunctionStmt(func_name, condition, statements)

        first_stmt = self.statement()
        statements.append(first_stmt)

        while self.current_token[0] == "SEMICOLON":
            self.expect("SEMICOLON")
            if self.current_token[0] == "EOF":
                break
            statements.append(self.statement())

        return FunctionStmt(func_name, condition, statements)


class Runtime:
    def __init__(self):
        self.variables = {}

    def evaluate(self, node):
        if isinstance(node, Program):
            for stmt in node.statements:
                self.evaluate(stmt)

        elif isinstance(node, EncryptStmt):
            data = self.get_value(node.data)
            key = self.get_value(node.key)
            print(f"[Encrypt] Data '{data}' with key '{key}'")

        elif isinstance(node, SendStmt):
            data = self.get_value(node.data)
            target = self.get_value(node.target)
            print(f"[Send] Sending '{data}' to '{target}'")

        elif isinstance(node, DenyStmt):
            condition = self.eval_condition(node.condition)
            if condition:
                print("[Deny] Access denied due to condition:", node.condition)
            else:
                print("[Deny] Access allowed")

        elif isinstance(node, AssignStmt):
            value = self.get_value(node.expr)
            self.variables[node.identifier.name] = value
            print(f"[Assign] {node.identifier.name} = {value}")

        elif isinstance(node, ConditionalStmt):
            cond = self.eval_condition(node.condition)
            if cond:
                for stmt in node.statements:
                    self.evaluate(stmt)

        elif isinstance(node, FunctionStmt):
            if node.condition is None or self.eval_condition(node.condition):
                if node.func_name == "ketamine":
                    print("[Ketamine] Condition met, executing statements:")
                    for stmt in node.statements:
                        self.evaluate(stmt)

                elif node.func_name == "dmt":
                    print("[DMT] Collector activated:")
                    collected = []
                    for stmt in node.statements:
                        if isinstance(stmt, AssignStmt):
                            collected.append(stmt.identifier.name)
                        self.evaluate(stmt)
                    print(f"[DMT] Collected variables: {collected}")

                elif node.func_name == "arch":
                    print("[Arch] Archiving statements:")
                    for stmt in node.statements:
                        self.evaluate(stmt)
                    print("[Arch] Archive complete.")

                elif node.func_name == "dark":
                    print("[Dark] Executing mysterious dark function:")
                    for stmt in node.statements:
                        self.evaluate(stmt)

                elif node.func_name == "void":
                    print("[Void] Emptiness voided all effects here. No action taken.")

                else:
                    raise RuntimeError(f"Unknown function: {node.func_name}")

        # New support for mythical function calls in expressions
        elif isinstance(node, FunctionCall):
            args_evaluated = [self.get_value(arg) for arg in node.args]
            return self.call_mythical_function(node.func_name, args_evaluated)

        elif isinstance(node, BinaryOp):
            left = self.get_value(node.left)
            right = self.get_value(node.right)
            op = node.op
            return self.apply_op(left, op, right)

        elif isinstance(node, Identifier):
            return self.get_value(node)

        elif isinstance(node, Literal):
            return node.value

        else:
            raise RuntimeError(f"Unknown node type: {node}")

    def get_value(self, node):
        if isinstance(node, Identifier):
            if node.name in self.variables:
                return self.variables[node.name]
            else:
                # Keep your original special vars behavior
                if node.name in ("access", "admin", "user", "userRole"):
                    return node.name
                raise RuntimeError(f"Undefined variable: {node.name}")
        elif isinstance(node, Literal):
            return node.value
        elif isinstance(node, FunctionCall):
            return self.evaluate(node)
        elif isinstance(node, BinaryOp):
            return self.evaluate(node)
        else:
            raise RuntimeError(f"Cannot get value of node: {node}")

    def eval_condition(self, node):
        if isinstance(node, BinaryOp):
            left = self.get_value(node.left)
            right = self.get_value(node.right)
            op = node.op
            if op == "==":
                return left == right
            elif op in ("!=", "≠"):
                return left != right
            elif op == "<":
                return left < right
            elif op == ">":
                return left > right
            elif op == "≤":
                return left <= right
            elif op == "≥":
                return left >= right
            elif op == "&":
                return bool(left) and bool(right)
            elif op == "|":
                return bool(left) or bool(right)
            elif op == "^":
                return bool(left) ^ bool(right)
            elif op == "+":
                return left + right
            elif op == "-":
                return left - right
            elif op == "*":
                return left * right
            elif op == "/":
                if right == 0:
                    raise RuntimeError("Division by zero")
                return left / right
            else:
                raise RuntimeError(f"Unknown operator in condition: {op}")
        else:
            return self.get_value(node)

    def apply_op(self, left, op, right):
        # Arithmetic and logical ops for BinaryOp evaluation
        if op == "+":
            return left + right
        elif op == "-":
            return left - right
        elif op == "*":
            return left * right
        elif op == "/":
            if right == 0:
                raise RuntimeError("Division by zero")
            return left / right
        elif op == "&":
            return bool(left) and bool(right)
        elif op == "|":
            return bool(left) or bool(right)
        elif op == "^":
            return bool(left) ^ bool(right)
        elif op == "==":
            return left == right
        elif op in ("!=", "≠"):
            return left != right
        elif op == "<":
            return left < right
        elif op == ">":
            return left > right
        elif op == "≤":
            return left <= right
        elif op == "≥":
            return left >= right
        else:
            raise RuntimeError(f"Unknown operator: {op}")

    # New mythical functions dispatcher
    def call_mythical_function(self, func_name, args):
        func_name_lower = func_name.lower()
        # Example swag mythical functions:

        if func_name_lower == "phoenix":
            # phoenix(x): multiplies input by 10, swag style
            if len(args) != 1:
                raise RuntimeError(f"phoenix() expects 1 argument, got {len(args)}")
            print(f"[Mythical] phoenix invoked with arg {args[0]}")
            return args[0] * 10

        elif func_name_lower == "leviathan":
            # leviathan(x,y): x ^ y (power)
            if len(args) != 2:
                raise RuntimeError(f"leviathan() expects 2 arguments, got {len(args)}")
            print(f"[Mythical] leviathan invoked with args {args}")
            return args[0] ** args[1]

        elif func_name_lower == "seraph":
            # seraph(): returns 777 constant
            if len(args) != 0:
                raise RuntimeError(f"seraph() expects 0 arguments, got {len(args)}")
            print("[Mythical] seraph invoked")
            return 777

        else:
            raise RuntimeError(f"Unknown mythical function: {func_name}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: zerith <filename.zerith>")
        sys.exit(1)

    filename = sys.argv[1]
    if not filename.endswith(".zerith"):
        print("ERROR!: expected a .zerith file extension. this is being reported. please put .zerith at the end.")

    with open(filename, "r", encoding="utf-8") as f:
        code = f.read()

    lexer = Lexer(code)
    tokens = lexer.tokenize()

    parser = Parser(tokens)
    ast = parser.parse()

    runtime = Runtime()
    runtime.evaluate(ast)
