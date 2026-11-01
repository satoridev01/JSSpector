//! Guards: conditions that, once they hold, make a value safe.
//!
//! `if (!isValid(x)) return;` cleans `x` after the `if`; `if (isValid(x)) { ... }` cleans it inside
//! the block. Which calls validate comes from the packs (`sanitizers.validators`); the shapes
//! (negation, `||` after an exit, `&&` inside a block, `typeof`, equality with a literal) are
//! language-level. Values are named by access path (`x`, `req.query.id`).

use oxc_ast::ast::{
    Argument, BinaryOperator, Expression, LogicalOperator, Statement, UnaryOperator,
};

use super::models::{has, model};

/// What a guard established about a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fact {
    /// Validated or compared with a constant: no longer attacker-controlled in a useful way.
    Clean,
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
                    out.push((key, Fact::Clean));
                }
            }
        }
        _ => {}
    }
}

/// A validator call that returned true: `isValid(x)`, `/^\w+$/.test(x)`, `ALLOWED.includes(x)`,
/// `p.startsWith(base)`.
fn validator_call(call: &oxc_ast::ast::CallExpression<'_>, out: &mut Vec<(String, Fact)>) {
    let validators = &model().validators;
    let callee = call.callee.get_inner_expression();
    let name = match callee {
        Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
        other => other
            .as_member_expression()
            .and_then(|m| m.static_property_name())
            .and_then(|n| n.as_str().map(str::to_owned)),
    };
    let Some(name) = name else { return };
    let qualified = callee
        .as_member_expression()
        .and_then(|m| Some(format!("{}.{name}", path_key(m.object())?)));
    let lower = name.to_ascii_lowercase();
    let validates_args = has(validators, &name)
        || qualified.as_deref().is_some_and(|q| has(validators, q))
        || (is_predicate(&lower)
            && model()
                .validator_words
                .iter()
                .any(|w| lower.contains(w.as_str()))
            && !model()
                .rejecter_words
                .iter()
                .any(|w| lower.contains(w.as_str())));
    if validates_args {
        for argument in &call.arguments {
            if let Some(key) = argument.as_expression().and_then(path_key) {
                out.push((key, Fact::Clean));
            }
        }
    }
    // Checks on the value itself: `p.startsWith(base)`, `v.match(/^\d+$/)`.
    if has(&model().receiver_validators, &name)
        && let Some(member) = callee.as_member_expression()
        && let Some(key) = path_key(member.object())
    {
        out.push((key, Fact::Clean));
    }
}

/// `isX`, `hasX`, `canX`, `checkX`...: a name that reads as a yes/no question.
pub fn is_predicate(lower: &str) -> bool {
    [
        "is", "has", "can", "check", "validate", "verify", "ensure", "assert",
    ]
    .iter()
    .any(|p| lower.starts_with(p))
}

/// A rejecting check that returned false: `isPathTraversal(x)`, `x.includes('..')`.
fn rejecter_call(call: &oxc_ast::ast::CallExpression<'_>, out: &mut Vec<(String, Fact)>) {
    let callee = call.callee.get_inner_expression();
    let name = match callee {
        Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
        other => other
            .as_member_expression()
            .and_then(|m| m.static_property_name())
            .and_then(|n| n.as_str().map(str::to_owned)),
    };
    let Some(name) = name else { return };
    let lower = name.to_ascii_lowercase();
    if is_predicate(&lower)
        && model()
            .rejecter_words
            .iter()
            .any(|w| lower.contains(w.as_str()))
    {
        for argument in &call.arguments {
            if let Some(key) = argument.as_expression().and_then(path_key) {
                out.push((key, Fact::Clean));
            }
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
        out.push((key, Fact::Clean));
    }
}

/// `check(x, String)`-style statements: assertions that throw unless `x` has a type.
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
    if has(&model().type_assertions, callee.name.as_str())
        && let Some(Argument::Identifier(id)) = call.arguments.first()
    {
        out.push((id.name.as_str().to_owned(), Fact::Scalar));
    } else if has(&model().validators, callee.name.as_str()) {
        // `assertSafe(x)` used as a statement throws on bad input.
        validator_call(call, out);
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
