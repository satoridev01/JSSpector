//! Guards: conditions that, once they hold, make a value safe (for some classes).
//!
//! `if (!isValid(x)) return;` cleans `x` after the `if`; `if (isValid(x)) { ... }` cleans it inside
//! the block. Which calls validate comes from the packs (`sanitizers.validators`); the shapes
//! (negation, `||` after an exit, `&&` inside a block, `typeof`, equality with a literal) are
//! language-level. Values are named by access path (`x`, `req.query.id`).
//!
//! A clean fact says for which vulnerability classes the value is safe: a numeric or allowlist
//! check is safe everywhere, `!p.includes('..')` only for paths, an anchored regex for the
//! classes whose dangerous characters it excludes, a format check such as `isURL` for none.

use jss_core::VulnClass;
use oxc_ast::ast::{
    Argument, BinaryOperator, Expression, LogicalOperator, Statement, UnaryOperator,
};

use super::class_bit;
use super::models::{has, model};

/// Every class.
pub const ALL: u8 = u8::MAX;

/// What a guard established about a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fact {
    /// Validated: no longer attacker-controlled in a useful way for these classes
    /// (bits of [`class_bit`]; [`ALL`] for every class).
    Clean(u8),
    /// Known to be a string (or number/boolean), never an object.
    Scalar,
}

/// The access path of an identifier or a chain of static members: `req.query.id`.
pub fn path_key(expr: &Expression<'_>) -> Option<String> {
    match expr.get_inner_expression() {
        Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
        Expression::StaticMemberExpression(m) => Some(format!(
            "{}.{}",
            path_key(&m.object)?,
            m.property.name.as_str()
        )),
        Expression::ComputedMemberExpression(m) => match m.expression.get_inner_expression() {
            Expression::StringLiteral(lit) => {
                Some(format!("{}.{}", path_key(&m.object)?, lit.value.as_str()?))
            }
            _ => None,
        },
        Expression::ChainExpression(chain) => {
            chain
                .expression
                .as_member_expression()
                .and_then(|m| match m {
                    oxc_ast::ast::MemberExpression::StaticMemberExpression(s) => Some(format!(
                        "{}.{}",
                        path_key(&s.object)?,
                        s.property.name.as_str()
                    )),
                    _ => None,
                })
        }
        _ => None,
    }
}

/// [`path_key`] of a member expression.
pub fn member_key(member: &oxc_ast::ast::MemberExpression<'_>) -> Option<String> {
    use oxc_ast::ast::MemberExpression as M;
    let property = match member {
        M::StaticMemberExpression(s) => s.property.name.as_str().to_owned(),
        M::ComputedMemberExpression(c) => match c.expression.get_inner_expression() {
            Expression::StringLiteral(lit) => lit.value.as_str()?.to_owned(),
            _ => return None,
        },
        M::PrivateFieldExpression(_) => return None,
    };
    Some(format!("{}.{property}", path_key(member.object())?))
}

/// The facts that hold when `test` evaluates to `truth`.
pub fn facts(test: &Expression<'_>, truth: bool, out: &mut Vec<(String, Fact)>) {
    match test.get_inner_expression() {
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::LogicalNot => {
            facts(&u.argument, !truth, out);
        }
        Expression::LogicalExpression(l) => match (l.operator, truth) {
            // `!(a || b)`: neither holds; `a && b`: both hold.
            (LogicalOperator::Or, false) | (LogicalOperator::And, true) => {
                facts(&l.left, truth, out);
                facts(&l.right, truth, out);
            }
            // `a || b` held (or `a && b` failed): only what both sides establish.
            (LogicalOperator::Or, true) | (LogicalOperator::And, false) => {
                let (mut left, mut right) = (Vec::new(), Vec::new());
                facts(&l.left, truth, &mut left);
                facts(&l.right, truth, &mut right);
                out.extend(left.into_iter().filter(|fact| right.contains(fact)));
            }
            _ => {}
        },
        Expression::CallExpression(call) if truth => validator_call(call, out),
        // `if (isPathTraversal(x)) throw ...`: a check that is true for bad input, false here.
        Expression::CallExpression(call) => rejecter_call(call, out),
        Expression::BinaryExpression(b) => {
            let equal = matches!(
                b.operator,
                BinaryOperator::StrictEquality | BinaryOperator::Equality
            );
            let unequal = matches!(
                b.operator,
                BinaryOperator::StrictInequality | BinaryOperator::Inequality
            );
            if !(equal && truth || unequal && !truth) {
                return;
            }
            // `typeof x === 'string'`
            for (a, other) in [(&b.left, &b.right), (&b.right, &b.left)] {
                if let Expression::UnaryExpression(u) = a.get_inner_expression()
                    && u.operator == UnaryOperator::Typeof
                    && let Expression::StringLiteral(kind) = other.get_inner_expression()
                    && matches!(kind.value.as_str(), Some("string" | "number" | "boolean"))
                    && let Some(key) = path_key(&u.argument)
                {
                    out.push((key, Fact::Scalar));
                    return;
                }
            }
            // `x === 'admin'`: the value is a constant from here on.
            for (a, other) in [(&b.left, &b.right), (&b.right, &b.left)] {
                if matches!(
                    other.get_inner_expression(),
                    Expression::StringLiteral(_) | Expression::NumericLiteral(_)
                ) && let Some(key) = path_key(a)
                {
                    out.push((key, Fact::Clean(ALL)));
                }
            }
        }
        _ => {}
    }
}

/// The callee's name (last segment) and, for a member call, its qualified form (`validator.isURL`).
fn callee_names(call: &oxc_ast::ast::CallExpression<'_>) -> Option<(String, Option<String>)> {
    let callee = call.callee.get_inner_expression();
    let name = match callee {
        Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
        other => other
            .as_member_expression()
            .and_then(|m| m.static_property_name())
            .and_then(|n| n.as_str().map(str::to_owned)),
    }?;
    let qualified = callee
        .as_member_expression()
        .and_then(|m| Some(format!("{}.{name}", path_key(m.object())?)));
    Some((name, qualified))
}

/// The classes of the pack's `sanitizers.scoped` lists that `matches` selects, if any:
/// `isPathInside` is a path check, `isPrivateIp` an SSRF one, `isURL` (under `none`) a format
/// check that covers no class.
fn scoped_mask(matches: impl Fn(&[String]) -> bool) -> Option<u8> {
    let mut found = None;
    for (class, names) in &model().scoped_sanitizers {
        if matches(names) {
            let bit = class_from_name(class).map_or(0, class_bit);
            found = Some(found.unwrap_or(0) | bit);
        }
    }
    found
}

fn class_from_name(name: &str) -> Option<VulnClass> {
    [
        VulnClass::CommandInjection,
        VulnClass::CodeInjection,
        VulnClass::SqlInjection,
        VulnClass::NosqlInjection,
        VulnClass::PathTraversal,
        VulnClass::Ssrf,
        VulnClass::Xss,
        VulnClass::PrototypePollution,
    ]
    .into_iter()
    .find(|class| class.name() == name)
}

/// The classes a listed check or clearing call covers: its scoped lists, else every class.
pub fn named_mask(name: &str, qualified: Option<&str>) -> u8 {
    scoped_mask(|list| has(list, name) || qualified.is_some_and(|q| has(list, q))).unwrap_or(ALL)
}

/// The classes a name-word check covers: the scoped lists of the words in its name
/// (`isWithinRoot` -> paths), else every class.
fn word_mask(lower: &str) -> u8 {
    scoped_mask(|list| list.iter().any(|w| lower.contains(w.as_str()))).unwrap_or(ALL)
}

/// The access path of a call's first argument.
fn first_key(call: &oxc_ast::ast::CallExpression<'_>) -> Option<String> {
    call.arguments
        .first()
        .and_then(Argument::as_expression)
        .and_then(path_key)
}

/// A validator call that returned true: `isValid(x)`, `/^\w+$/.test(x)`, `ALLOWED.includes(x)`,
/// `p.startsWith(base)`.
fn validator_call(call: &oxc_ast::ast::CallExpression<'_>, out: &mut Vec<(String, Fact)>) {
    let model = model();
    let Some((name, qualified)) = callee_names(call) else {
        return;
    };
    let callee = call.callee.get_inner_expression();
    let lower = name.to_ascii_lowercase();
    // `/^[\w-]+$/.test(x)`: what the pattern admits decides the classes.
    if let Some(member) = callee.as_member_expression()
        && let Expression::RegExpLiteral(regex) = member.object().get_inner_expression()
    {
        if let Some(set) = anchored_allowlist(
            regex.regex.pattern.text.as_str(),
            &regex.regex.flags.to_string(),
        ) && let Some(key) = first_key(call)
        {
            out.push((key, Fact::Clean(mask(&set))));
        }
        return;
    }
    let listed = has(&model.validators, &name)
        || qualified
            .as_deref()
            .is_some_and(|q| has(&model.validators, q));
    // `isValidName(x)`, `isSafePath(x)`: a validator word right after the yes/no prefix, never
    // negated (`isNotAllowed`), and only for the first argument (`isValidPassword(user, pass)`).
    let worded = !listed && predicate_word(&lower).is_some();
    if listed || worded {
        let classes = if listed {
            named_mask(&name, qualified.as_deref())
        } else {
            word_mask(&lower)
        };
        let count = if listed { call.arguments.len() } else { 1 };
        for argument in call.arguments.iter().take(count) {
            let Some(key) = argument.as_expression().and_then(path_key) else {
                continue;
            };
            if classes == 0 {
                // A format check (`isEmail`): a string, nothing more.
                out.push((key, Fact::Scalar));
            } else {
                out.push((key, Fact::Clean(classes)));
            }
        }
    }
    // Checks on the value itself: `p.startsWith(base)`, `v.match(/^\d+$/)`.
    if has(&model.receiver_validators, &name)
        && let Some(member) = callee.as_member_expression()
        && let Some(key) = path_key(member.object())
    {
        let argument = call
            .arguments
            .first()
            .and_then(Argument::as_expression)
            .map(Expression::get_inner_expression);
        let classes = match argument {
            // `v.match(/^\d+$/)`
            Some(Expression::RegExpLiteral(regex)) => anchored_allowlist(
                regex.regex.pattern.text.as_str(),
                &regex.regex.flags.to_string(),
            )
            .map(|set| mask(&set)),
            // `url.startsWith('https://api.example.com/')`: the origin is fixed; a bare scheme
            // or a relative prefix (`'uploads/'` on raw input) proves nothing.
            Some(Expression::StringLiteral(literal)) => literal
                .value
                .as_str()
                .filter(|text| fixed_origin(text))
                .map(|_| class_bit(VulnClass::Ssrf)),
            // `resolved.startsWith(base + path.sep)`: contained in a base directory or origin.
            Some(_) => Some(class_bit(VulnClass::PathTraversal) | class_bit(VulnClass::Ssrf)),
            None => None,
        };
        if let Some(classes) = classes.filter(|c| *c != 0) {
            out.push((key, Fact::Clean(classes)));
        }
    }
}

/// `https://host/...`: a scheme, a host and the start of a path.
fn fixed_origin(text: &str) -> bool {
    text.split_once("://").is_some_and(|(scheme, rest)| {
        !scheme.is_empty()
            && rest
                .split_once('/')
                .is_some_and(|(host, _)| !host.is_empty() && !host.contains('@'))
    })
}

/// `isX`, `hasX`, `canX`, `checkX`...: a name that reads as a yes/no question.
pub fn is_predicate(lower: &str) -> bool {
    predicate_prefix(lower).is_some()
}

fn predicate_prefix(lower: &str) -> Option<&'static str> {
    [
        "is", "has", "can", "check", "validate", "verify", "ensure", "assert",
    ]
    .into_iter()
    .find(|p| lower.starts_with(p))
}

/// The validator word a predicate name starts with after its prefix: `isvalidname` -> `valid`.
/// A negated name (`isnotvalid`, `isunsafe`, `isinvalid`) has none.
fn predicate_word(lower: &str) -> Option<&'static str> {
    let prefix = predicate_prefix(lower)?;
    let rest = lower.get(prefix.len()..)?;
    if rest.starts_with("not") || rest.starts_with("un") || rest.starts_with("invalid") {
        return None;
    }
    if model()
        .rejecter_words
        .iter()
        .any(|w| lower.contains(w.as_str()))
    {
        return None;
    }
    model()
        .validator_words
        .iter()
        .find(|w| rest.starts_with(w.as_str()))
        .map(String::as_str)
}

/// A rejecting check that returned false: `isPathTraversal(x)`, `x.includes('..')`,
/// `/\.\./.test(x)`.
fn rejecter_call(call: &oxc_ast::ast::CallExpression<'_>, out: &mut Vec<(String, Fact)>) {
    let Some((name, _)) = callee_names(call) else {
        return;
    };
    let callee = call.callee.get_inner_expression();
    let lower = name.to_ascii_lowercase();
    // `/\.\./.test(p)` or `/[;&|`$]/.test(cmd)` was false: the value has none of that.
    if let Some(member) = callee.as_member_expression()
        && let Expression::RegExpLiteral(regex) = member.object().get_inner_expression()
    {
        let classes = denylist_mask(regex.regex.pattern.text.as_str());
        if classes != 0
            && let Some(key) = first_key(call)
        {
            out.push((key, Fact::Clean(classes)));
        }
        return;
    }
    if is_predicate(&lower)
        && model()
            .rejecter_words
            .iter()
            .any(|w| lower.contains(w.as_str()))
    {
        // `isPathTraversal(p)` covers paths, `isPrivateIp(host)` SSRF (pack scopes).
        let classes = word_mask(&lower);
        if classes != 0
            && let Some(key) = first_key(call)
        {
            out.push((key, Fact::Clean(classes)));
        }
        return;
    }
    // `p.includes('..')` (or another marker) was false: the receiver has no traversal.
    if has(&model().receiver_rejecters, &name)
        && let Some(Argument::StringLiteral(marker)) = call.arguments.first()
        && marker.value.as_str().is_some_and(|m| {
            model()
                .rejected_markers
                .iter()
                .any(|r| m.contains(r.as_str()))
        })
        && let Some(member) = callee.as_member_expression()
        && let Some(key) = path_key(member.object())
    {
        out.push((key, Fact::Clean(class_bit(VulnClass::PathTraversal))));
    }
}

/// `check(x, String)`-style statements: assertions that throw unless `x` has a type; and
/// `assertSafe(x)`-style calls that throw on bad input.
pub fn assertion(statement: &Statement<'_>, out: &mut Vec<(String, Fact)>) {
    let Statement::ExpressionStatement(s) = statement else {
        return;
    };
    let Expression::CallExpression(call) = s.expression.get_inner_expression() else {
        return;
    };
    let Expression::Identifier(callee) = call.callee.get_inner_expression() else {
        return;
    };
    let name = callee.name.as_str();
    if has(&model().type_assertions, name) {
        // `check(x, String)` or `check(x, [Number])`; `check(x, Object)` or `Match.Any` still
        // admit an operator object.
        let scalar = call
            .arguments
            .get(1)
            .and_then(Argument::as_expression)
            .is_some_and(scalar_pattern);
        if scalar && let Some(Argument::Identifier(id)) = call.arguments.first() {
            out.push((id.name.as_str().to_owned(), Fact::Scalar));
        }
        return;
    }
    // An assertion throws (`assertSafe(x)`, `ensureValid(x)`); a boolean whose result is
    // dropped (`validate(x);`, `isSafe(x);`) proves nothing.
    let lower = name.to_ascii_lowercase();
    if (lower.starts_with("assert") || lower.starts_with("ensure"))
        && (has(&model().validators, name) || predicate_word(&lower).is_some())
    {
        validator_call(call, out);
    }
}

/// Whether a type pattern rules out operator objects: anything but a pattern that admits an
/// object (`Object`, `Match.Any`, `Match.ObjectIncluding(...)`), a wrapper of one
/// (`Match.Optional(Object)`), or a shape or array with one inside.
fn scalar_pattern(pattern: &Expression<'_>) -> bool {
    let admits_object = |name: &str| has(&model().object_patterns, name);
    match pattern.get_inner_expression() {
        Expression::ArrayExpression(array) => array
            .elements
            .iter()
            .all(|e| e.as_expression().is_none_or(scalar_pattern)),
        Expression::ObjectExpression(object) => object.properties.iter().all(|p| match p {
            oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) => scalar_pattern(&p.value),
            oxc_ast::ast::ObjectPropertyKind::SpreadProperty(_) => false,
        }),
        Expression::CallExpression(call) => {
            !path_key(&call.callee).is_some_and(|name| admits_object(&name))
                && call
                    .arguments
                    .iter()
                    .filter_map(Argument::as_expression)
                    .all(scalar_pattern)
        }
        other => !path_key(other).is_some_and(|name| admits_object(&name)),
    }
}

/// Whether `statement` always leaves the enclosing block: return, throw, break, continue.
pub fn exits(statement: &Statement<'_>) -> bool {
    match statement {
        Statement::ReturnStatement(_)
        | Statement::ThrowStatement(_)
        | Statement::BreakStatement(_)
        | Statement::ContinueStatement(_) => true,
        Statement::BlockStatement(b) => b.body.last().is_some_and(exits),
        Statement::IfStatement(i) => {
            exits(&i.consequent) && i.alternate.as_ref().is_some_and(exits)
        }
        _ => false,
    }
}

/// The ASCII characters a pattern can match (plus whether it can match others).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CharSet {
    ascii: u128,
    other: bool,
}

impl CharSet {
    fn add(&mut self, c: char) {
        match u32::from(c) {
            n @ 0..=127 => self.ascii |= 1u128 << n,
            _ => self.other = true,
        }
    }

    fn add_range(&mut self, from: char, to: char) {
        for code in u32::from(from)..=u32::from(to) {
            match char::from_u32(code) {
                Some(c) if code < 128 => self.add(c),
                _ => self.other = true,
            }
        }
    }

    fn add_word(&mut self) {
        self.add_range('a', 'z');
        self.add_range('A', 'Z');
        self.add_range('0', '9');
        self.add('_');
    }

    fn contains(&self, c: char) -> bool {
        let n = u32::from(c);
        n < 128 && self.ascii & (1u128 << n) != 0
    }

    fn any(&self, chars: &str) -> bool {
        chars.chars().any(|c| self.contains(c))
    }

    fn has_letters(&self) -> bool {
        ('a'..='z').chain('A'..='Z').any(|c| self.contains(c))
    }

    /// With the `i` flag: both cases of every letter.
    fn fold_case(&mut self) {
        for c in ('a'..='z').chain('A'..='Z') {
            if self.contains(c) {
                self.add(c.to_ascii_uppercase());
                self.add(c.to_ascii_lowercase());
            }
        }
    }
}

/// The characters an allowlist regex admits: an anchored `^...$` pattern, without the `m` flag
/// (which anchors lines, not the value), made of character classes, escapes and literals with
/// groups and quantifiers. `None` when it can match anything (`.`, `\S`, a negated class) or
/// is not anchored at both ends.
pub fn anchored_allowlist(pattern: &str, flags: &str) -> Option<CharSet> {
    if flags.contains('m') {
        return None;
    }
    let body = pattern.strip_prefix('^')?;
    let body = body.strip_suffix('$')?;
    if body.ends_with('\\') {
        // `\$` at the end: a literal dollar, not an anchor.
        return None;
    }
    let mut set = sequence(body)?;
    if flags.contains('i') {
        set.fold_case();
    }
    Some(set)
}

/// `set` with both cases of its letters (the `i` flag).
pub fn with_both_cases(mut set: CharSet) -> CharSet {
    set.fold_case();
    set
}

/// The characters a strip keeps: `s.replace(/[^a-z0-9]/g, '')` keeps `a-z0-9`.
pub fn negated_class(pattern: &str) -> Option<CharSet> {
    let class = pattern
        .strip_suffix('+')
        .or_else(|| pattern.strip_suffix('*'))
        .unwrap_or(pattern);
    let inner = class.strip_prefix("[^")?.strip_suffix(']')?;
    class_body(inner)
}

/// The characters a regex body (between anchors) can match.
fn sequence(body: &str) -> Option<CharSet> {
    let mut set = CharSet::default();
    let mut chars = body.chars().peekable();
    let mut depth = 0usize;
    while let Some(c) = chars.next() {
        match c {
            '\\' => escape(chars.next()?, &mut set)?,
            '[' => {
                let mut inner = String::new();
                let mut escaped = false;
                loop {
                    let next = chars.next()?;
                    if escaped {
                        inner.push('\\');
                        inner.push(next);
                        escaped = false;
                    } else if next == '\\' {
                        escaped = true;
                    } else if next == ']' {
                        break;
                    } else {
                        inner.push(next);
                    }
                }
                if inner.starts_with('^') {
                    return None;
                }
                let class = class_body(&inner)?;
                set.ascii |= class.ascii;
                set.other |= class.other;
            }
            '.' => return None,
            '(' => {
                if chars.peek() == Some(&'?') {
                    let mut look = chars.clone();
                    look.next();
                    match look.next() {
                        // `(?:...)`: a plain group.
                        Some(':') => {
                            chars.next();
                            chars.next();
                            depth += 1;
                        }
                        // `(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)`: assertions consume
                        // nothing.
                        Some('=' | '!' | '<') => {
                            let mut nesting = 1usize;
                            for skipped in chars.by_ref() {
                                match skipped {
                                    '(' => nesting += 1,
                                    ')' => {
                                        nesting -= 1;
                                        if nesting == 0 {
                                            break;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => return None,
                    }
                } else {
                    depth += 1;
                }
            }
            ')' => depth = depth.checked_sub(1)?,
            // `^a|b$` anchors each side separately: not an allowlist.
            '|' if depth == 0 => return None,
            '|' | '?' | '*' | '+' | '^' | '$' => {}
            '{' => {
                for skipped in chars.by_ref() {
                    if skipped == '}' {
                        break;
                    }
                }
            }
            literal => set.add(literal),
        }
    }
    Some(set)
}

/// One escape: `\w`, `\d`, `\s` and escaped literals; `\W`, `\D`, `\S`, `\p{...}` match too much.
fn escape(c: char, set: &mut CharSet) -> Option<()> {
    match c {
        'w' => set.add_word(),
        'd' => set.add_range('0', '9'),
        's' => {
            for space in [' ', '\t', '\n', '\r', '\u{b}', '\u{c}'] {
                set.add(space);
            }
            set.other = true;
        }
        'b' | 'B' => {}
        'W' | 'D' | 'S' | 'p' | 'P' | 'x' | 'u' => return None,
        'n' => set.add('\n'),
        't' => set.add('\t'),
        'r' => set.add('\r'),
        other => set.add(other),
    }
    Some(())
}

/// The characters of a character class body (`a-z0-9_.\-`).
fn class_body(inner: &str) -> Option<CharSet> {
    let mut set = CharSet::default();
    let mut items: Vec<Option<char>> = Vec::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let next = chars.next()?;
            match next {
                'w' | 'd' | 's' | 'W' | 'D' | 'S' | 'p' | 'P' | 'x' | 'u' => {
                    escape(next, &mut set)?;
                    items.push(None);
                }
                'n' => items.push(Some('\n')),
                't' => items.push(Some('\t')),
                'r' => items.push(Some('\r')),
                other => items.push(Some(other)),
            }
        } else {
            items.push(Some(c));
        }
    }
    let mut index = 0;
    while index < items.len() {
        match (items.get(index), items.get(index + 1), items.get(index + 2)) {
            (Some(Some(from)), Some(Some('-')), Some(Some(to))) if from <= to => {
                set.add_range(*from, *to);
                index += 3;
            }
            (Some(Some(c)), _, _) => {
                set.add(*c);
                index += 1;
            }
            _ => index += 1,
        }
    }
    Some(set)
}

/// The classes a value made only of `set`'s characters is safe for.
pub fn mask(set: &CharSet) -> u8 {
    let mut classes = ALL;
    if set.other || set.any(";|&$`(){}<>\\\n\r\t \"'!*?~#") {
        classes &= !(class_bit(VulnClass::CommandInjection) | class_bit(VulnClass::CodeInjection));
    }
    if set.other || set.any("'\"`\\ \t\n\r;()/*#=") {
        classes &= !class_bit(VulnClass::SqlInjection);
    }
    if set.any("<>\"'`") {
        classes &= !class_bit(VulnClass::Xss);
    }
    // `/` or `\` allow traversal (`../`) and absolute paths.
    if set.other || set.any("/\\") {
        classes &= !class_bit(VulnClass::PathTraversal);
    }
    // A host needs letters or dots; digits alone are no URL start.
    if set.has_letters() || set.any(".:/@\\") {
        classes &= !class_bit(VulnClass::Ssrf);
    }
    // `__proto__`, `constructor`, `prototype` are made of letters.
    if set.has_letters() {
        classes &= !class_bit(VulnClass::PrototypePollution);
    }
    classes
}

/// The classes a denylist regex protects when it did not match: `/\.\./` for paths, a class of
/// shell metacharacters for commands.
fn denylist_mask(pattern: &str) -> u8 {
    let mut classes = 0;
    if pattern.contains("\\.\\.") {
        classes |= class_bit(VulnClass::PathTraversal);
    }
    if let Some(set) = pattern
        .strip_prefix('[')
        .and_then(|p| p.split_once(']'))
        .and_then(|(inner, _)| class_body(inner))
        && [';', '|', '&', '$', '`'].iter().all(|c| set.contains(*c))
    {
        classes |= class_bit(VulnClass::CommandInjection);
    }
    classes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classes(pattern: &str) -> Option<u8> {
        anchored_allowlist(pattern, "").map(|set| mask(&set))
    }

    #[test]
    fn allowlists_are_read_from_their_characters() {
        let path = class_bit(VulnClass::PathTraversal);
        let command = class_bit(VulnClass::CommandInjection);
        let sql = class_bit(VulnClass::SqlInjection);
        // Digits only: safe everywhere.
        assert_eq!(classes(r"^\d+$"), Some(ALL));
        assert_eq!(classes(r"^[0-9]{1,6}$"), Some(ALL));
        // A slug: safe for shells, SQL and paths, not as a host or an object key.
        let slug = classes(r"^[\w-]+$").unwrap();
        assert_ne!(slug & path, 0);
        assert_ne!(slug & command, 0);
        assert_ne!(slug & sql, 0);
        assert_eq!(slug & class_bit(VulnClass::Ssrf), 0);
        // A file path allowlist admits `../`.
        let file = classes(r"^[\w./-]+$").unwrap();
        assert_eq!(file & path, 0);
        assert_ne!(file & command, 0);
        // Not anchored at both ends, `.`, `m` flag, top-level alternation: no allowlist.
        assert_eq!(classes(r"^ls"), None);
        assert_eq!(classes(r"^.+$"), None);
        assert_eq!(anchored_allowlist(r"^\w+$", "m"), None);
        assert_eq!(classes(r"^a|b$"), None);
        assert!(classes(r"^(png|jpg)$").is_some());
        // Lookaheads consume nothing.
        assert_eq!(classes(r"^(?!\.)[\w]+$").map(|c| c & path != 0), Some(true));
    }

    #[test]
    fn strips_keep_their_class() {
        let kept = negated_class(r"[^a-z0-9_-]").map(|set| mask(&set)).unwrap();
        assert_ne!(kept & class_bit(VulnClass::PathTraversal), 0);
        // `[^\x20-\x7E]` strips control characters only: escapes we do not read keep nothing
        // certain, so it is no allowlist.
        assert!(negated_class(r"[^\x20-\x7E]").is_none());
    }

    #[test]
    fn origins_are_fixed_only_with_a_host() {
        assert!(fixed_origin("https://api.example.com/"));
        assert!(!fixed_origin("http"));
        assert!(!fixed_origin("https://"));
        assert!(!fixed_origin("uploads/"));
    }
}
