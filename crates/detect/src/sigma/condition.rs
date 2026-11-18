//! The `condition` expression of a Sigma rule.

const AGGREGATION: &str = "the condition uses \"|\"; aggregation is not supported";

/// The largest depth of parentheses and `not` in a condition.
const MAX_DEPTH: usize = 32;

/// A compiled condition. Each number is the index of a selection of the rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Condition {
    /// One selection.
    Selection(usize),
    /// `not`.
    Not(Box<Condition>),
    /// `and`.
    And(Vec<Condition>),
    /// `or`.
    Or(Vec<Condition>),
    /// `N of ...`: at least `count` of the selections match.
    AtLeast {
        /// The smallest number of selections that must match.
        count: usize,
        /// The selections.
        selections: Vec<usize>,
    },
    /// `all of ...`: each of the selections matches.
    All(Vec<usize>),
}

impl Condition {
    /// Evaluates the condition. `selection` returns the result of one selection.
    pub(crate) fn evaluate(&self, selection: &dyn Fn(usize) -> bool) -> bool {
        match self {
            Self::Selection(index) => selection(*index),
            Self::Not(inner) => !inner.evaluate(selection),
            Self::And(parts) => parts.iter().all(|part| part.evaluate(selection)),
            Self::Or(parts) => parts.iter().any(|part| part.evaluate(selection)),
            Self::AtLeast { count, selections } => {
                let mut matched = 0_usize;
                selections.iter().any(|index| {
                    matched += usize::from(selection(*index));
                    matched >= *count
                })
            }
            Self::All(selections) => selections.iter().all(|index| selection(*index)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token<'a> {
    Open,
    Close,
    Word(&'a str),
}

fn tokenize(text: &str) -> Vec<Token<'_>> {
    let mut tokens = Vec::new();
    let mut word_start: Option<usize> = None;
    for (index, character) in text.char_indices() {
        let is_break = character.is_whitespace() || character == '(' || character == ')';
        if !is_break {
            word_start.get_or_insert(index);
            continue;
        }
        if let Some(start) = word_start.take()
            && let Some(word) = text.get(start..index)
        {
            tokens.push(Token::Word(word));
        }
        match character {
            '(' => tokens.push(Token::Open),
            ')' => tokens.push(Token::Close),
            _ => {}
        }
    }
    if let Some(start) = word_start
        && let Some(word) = text.get(start..)
    {
        tokens.push(Token::Word(word));
    }
    tokens
}

fn is_keyword(word: &str, keyword: &str) -> bool {
    word.eq_ignore_ascii_case(keyword)
}

/// Returns `true` if a selection cannot have this name, because the condition gives the
/// word a meaning.
pub(crate) fn is_reserved(word: &str) -> bool {
    ["and", "or", "not", "of", "them"]
        .iter()
        .any(|keyword| is_keyword(word, keyword))
}

struct Parser<'a> {
    tokens: Vec<Token<'a>>,
    position: usize,
    names: &'a [String],
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&Token<'a>> {
        self.tokens.get(self.position)
    }

    fn peek_word(&self, offset: usize) -> Option<&'a str> {
        match self.tokens.get(self.position + offset) {
            Some(Token::Word(word)) => Some(word),
            _ => None,
        }
    }

    fn next_is_keyword(&self, keyword: &str) -> bool {
        self.peek_word(0)
            .is_some_and(|word| is_keyword(word, keyword))
    }

    fn or(&mut self, depth: usize) -> Result<Condition, String> {
        let mut parts = vec![self.and(depth)?];
        while self.next_is_keyword("or") {
            self.position += 1;
            parts.push(self.and(depth)?);
        }
        Ok(single_or(parts, Condition::Or))
    }

    fn and(&mut self, depth: usize) -> Result<Condition, String> {
        let mut parts = vec![self.not(depth)?];
        while self.next_is_keyword("and") {
            self.position += 1;
            parts.push(self.not(depth)?);
        }
        Ok(single_or(parts, Condition::And))
    }

    fn not(&mut self, depth: usize) -> Result<Condition, String> {
        if self.next_is_keyword("not") {
            if depth >= MAX_DEPTH {
                return Err(format!(
                    "the condition nests deeper than {MAX_DEPTH} levels"
                ));
            }
            self.position += 1;
            return Ok(Condition::Not(Box::new(self.not(depth + 1)?)));
        }
        self.primary(depth)
    }

    fn primary(&mut self, depth: usize) -> Result<Condition, String> {
        match self.peek().cloned() {
            None => Err("the condition ends where a selection must be".to_owned()),
            Some(Token::Close) => {
                Err("the condition has a \")\" where a selection must be".to_owned())
            }
            Some(Token::Open) => {
                if depth >= MAX_DEPTH {
                    return Err(format!(
                        "the condition nests deeper than {MAX_DEPTH} levels"
                    ));
                }
                self.position += 1;
                let inner = self.or(depth + 1)?;
                if self.peek() != Some(&Token::Close) {
                    return Err("the condition has a \"(\" with no \")\"".to_owned());
                }
                self.position += 1;
                Ok(inner)
            }
            Some(Token::Word(word)) => {
                if self.peek_word(1).is_some_and(|next| is_keyword(next, "of")) {
                    return self.quantifier(word);
                }
                self.position += 1;
                if word.contains('|') {
                    return Err(AGGREGATION.to_owned());
                }
                if is_reserved(word) {
                    return Err(format!(
                        "the condition has {word:?} where a selection must be"
                    ));
                }
                self.names
                    .iter()
                    .position(|name| name == word)
                    .map(Condition::Selection)
                    .ok_or_else(|| format!("the condition names the selection {word:?}, which the rule does not have"))
            }
        }
    }

    /// Parses `<count> of <pattern>`. The position is at the count.
    fn quantifier(&mut self, count_word: &str) -> Result<Condition, String> {
        self.position += 2;
        let Some(target) = self.peek_word(0) else {
            return Err("the condition has \"of\" with no selection pattern after it".to_owned());
        };
        self.position += 1;
        let selections: Vec<usize> = if is_keyword(target, "them") {
            (0..self.names.len()).collect()
        } else {
            self.names
                .iter()
                .enumerate()
                .filter(|(_, name)| name_matches(target, name))
                .map(|(index, _)| index)
                .collect()
        };
        if selections.is_empty() {
            return Err(format!(
                "the pattern {target:?} in the condition matches no selection"
            ));
        }
        if is_keyword(count_word, "all") {
            return Ok(Condition::All(selections));
        }
        let count = if is_keyword(count_word, "any") {
            1
        } else {
            count_word.parse::<usize>().map_err(|_| {
                format!("the condition has {count_word:?} before \"of\"; use a number or \"all\"")
            })?
        };
        if count == 0 || count > selections.len() {
            return Err(format!(
                "the condition needs {count} of {target:?}, which matches {} selections",
                selections.len()
            ));
        }
        Ok(Condition::AtLeast { count, selections })
    }
}

/// Returns `true` if a selection name matches a pattern. `*` matches zero or more
/// characters and `?` matches one character. The comparison keeps the case.
fn name_matches(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    let mut pattern_at = 0;
    let mut name_at = 0;
    // The position of the last `*`, and the position in the name that it matches up to.
    let mut star: Option<(usize, usize)> = None;
    while let Some(found) = name.get(name_at) {
        match pattern.get(pattern_at) {
            Some('*') => {
                star = Some((pattern_at, name_at));
                pattern_at += 1;
            }
            Some(expected) if *expected == '?' || expected == found => {
                pattern_at += 1;
                name_at += 1;
            }
            _ => match star {
                Some((star_at, matched_to)) => {
                    pattern_at = star_at + 1;
                    name_at = matched_to + 1;
                    star = Some((star_at, matched_to + 1));
                }
                None => return false,
            },
        }
    }
    pattern
        .get(pattern_at..)
        .is_some_and(|rest| rest.iter().all(|character| *character == '*'))
}

fn single_or(mut parts: Vec<Condition>, many: fn(Vec<Condition>) -> Condition) -> Condition {
    if parts.len() == 1
        && let Some(only) = parts.pop()
    {
        return only;
    }
    many(parts)
}

/// Parses a condition. `names` holds the names of the selections of the rule.
pub(crate) fn parse(text: &str, names: &[String]) -> Result<Condition, String> {
    let tokens = tokenize(text);
    if tokens.is_empty() {
        return Err("the condition is empty".to_owned());
    }
    let mut parser = Parser {
        tokens,
        position: 0,
        names,
    };
    let condition = parser.or(0)?;
    match parser.peek() {
        None => Ok(condition),
        Some(Token::Close) => Err("the condition has a \")\" with no \"(\"".to_owned()),
        Some(Token::Open) => {
            Err("the condition has a \"(\" where \"and\" or \"or\" must be".to_owned())
        }
        Some(Token::Word(word)) if word.contains('|') => Err(AGGREGATION.to_owned()),
        Some(Token::Word(word)) => Err(format!(
            "the condition has {word:?} where \"and\" or \"or\" must be"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> Vec<String> {
        ["selection_a", "selection_b", "selection_c", "filter"]
            .map(str::to_owned)
            .to_vec()
    }

    /// Evaluates `text` with the given results for the four selections.
    fn evaluate(text: &str, results: [bool; 4]) -> bool {
        let names = names();
        let condition = parse(text, &names).unwrap();
        condition.evaluate(&|index| results[index])
    }

    fn error(text: &str) -> String {
        parse(text, &names()).unwrap_err()
    }

    const T: bool = true;
    const F: bool = false;

    #[test]
    fn one_selection() {
        assert!(evaluate("selection_a", [T, F, F, F]));
        assert!(!evaluate("selection_a", [F, T, T, T]));
        assert_eq!(parse("filter", &names()).unwrap(), Condition::Selection(3));
    }

    #[test]
    fn and_needs_both_sides() {
        assert!(evaluate("selection_a and selection_b", [T, T, F, F]));
        assert!(!evaluate("selection_a and selection_b", [T, F, F, F]));
        assert!(!evaluate("selection_a and selection_b", [F, T, F, F]));
    }

    #[test]
    fn or_needs_one_side() {
        assert!(evaluate("selection_a or selection_b", [F, T, F, F]));
        assert!(evaluate("selection_a or selection_b", [T, F, F, F]));
        assert!(!evaluate("selection_a or selection_b", [F, F, T, T]));
    }

    #[test]
    fn not_inverts_and_can_repeat() {
        assert!(evaluate("not filter", [F, F, F, F]));
        assert!(!evaluate("not filter", [F, F, F, T]));
        assert!(evaluate("not not filter", [F, F, F, T]));
        assert!(evaluate("selection_a and not filter", [T, F, F, F]));
        assert!(!evaluate("selection_a and not filter", [T, F, F, T]));
    }

    #[test]
    fn and_binds_more_tightly_than_or() {
        // a or (b and c)
        assert!(evaluate(
            "selection_a or selection_b and selection_c",
            [T, F, F, F]
        ));
        assert!(!evaluate(
            "selection_a or selection_b and selection_c",
            [F, T, F, F]
        ));
        // (a and b) or c
        assert!(evaluate(
            "selection_a and selection_b or selection_c",
            [F, F, T, F]
        ));
        assert!(!evaluate(
            "selection_a and selection_b or selection_c",
            [T, F, F, F]
        ));
    }

    #[test]
    fn not_binds_more_tightly_than_and() {
        // (not a) and b
        assert!(!evaluate("not selection_a and selection_b", [F, F, F, F]));
        assert!(evaluate("not selection_a and selection_b", [F, T, F, F]));
        assert!(evaluate("not (selection_a and selection_b)", [F, F, F, F]));
    }

    #[test]
    fn parentheses_change_the_order() {
        assert!(!evaluate(
            "(selection_a or selection_b) and selection_c",
            [T, F, F, F]
        ));
        assert!(evaluate(
            "(selection_a or selection_b) and selection_c",
            [F, T, T, F]
        ));
        assert!(evaluate("((selection_a))", [T, F, F, F]));
        assert!(evaluate("(selection_a)and(selection_b)", [T, T, F, F]));
    }

    #[test]
    fn one_of_a_pattern_needs_one_matching_selection() {
        assert!(evaluate("1 of selection*", [F, F, T, F]));
        assert!(!evaluate("1 of selection*", [F, F, F, T]));
        assert!(evaluate("any of selection_*", [F, T, F, F]));
        assert_eq!(
            parse("1 of selection*", &names()).unwrap(),
            Condition::AtLeast {
                count: 1,
                selections: vec![0, 1, 2]
            }
        );
    }

    #[test]
    fn all_of_a_pattern_needs_each_matching_selection() {
        assert!(evaluate("all of selection*", [T, T, T, F]));
        assert!(!evaluate("all of selection*", [T, T, F, T]));
        assert_eq!(
            parse("all of selection_?", &names()).unwrap(),
            Condition::All(vec![0, 1, 2])
        );
    }

    #[test]
    fn a_number_of_a_pattern_needs_that_many_selections() {
        assert!(evaluate("2 of selection*", [T, F, T, F]));
        assert!(!evaluate("2 of selection*", [T, F, F, T]));
        assert!(evaluate("3 of selection*", [T, T, T, F]));
    }

    #[test]
    fn one_of_them_and_all_of_them_use_each_selection() {
        assert!(evaluate("1 of them", [F, F, F, T]));
        assert!(!evaluate("1 of them", [F, F, F, F]));
        assert!(evaluate("all of them", [T, T, T, T]));
        assert!(!evaluate("all of them", [T, T, T, F]));
    }

    #[test]
    fn quantifiers_combine_with_the_operators() {
        let text = "1 of selection* and not filter";
        assert!(evaluate(text, [F, T, F, F]));
        assert!(!evaluate(text, [F, T, F, T]));
        assert!(evaluate("not 1 of selection*", [F, F, F, T]));
        assert!(evaluate("(all of selection*) or filter", [F, F, F, T]));
    }

    #[test]
    fn keywords_ignore_case_and_selection_names_do_not() {
        assert!(evaluate("selection_a AND NOT filter", [T, F, F, F]));
        assert!(evaluate("ALL OF THEM", [T, T, T, T]));
        assert!(error("Selection_A").contains("\"Selection_A\""));
    }

    #[test]
    fn a_selection_pattern_matches_with_wildcards_and_keeps_the_case() {
        for (pattern, name, expected) in [
            ("selection*", "selection", true),
            ("selection*", "selection_a", true),
            ("selection*", "a_selection", false),
            ("*_a", "selection_a", true),
            ("*_a", "selection_ab", false),
            ("s*_*a", "selection_a", true),
            ("s*x*a", "selection_a", false),
            ("selection_?", "selection_a", true),
            ("selection_?", "selection_", false),
            ("*", "", true),
            ("", "", true),
            ("", "a", false),
            ("a*a", "a", false),
            ("a*a", "aba", true),
            ("**a**", "bab", true),
            ("SELECTION*", "selection_a", false),
        ] {
            assert_eq!(
                name_matches(pattern, name),
                expected,
                "{pattern:?} {name:?}"
            );
        }
        assert!(error("1 of SELECTION*").contains("matches no selection"));
    }

    #[test]
    fn a_pattern_that_matches_no_selection_is_an_error() {
        let message = error("all of nothing*");
        assert_eq!(
            message,
            "the pattern \"nothing*\" in the condition matches no selection"
        );
        assert!(error("1 of other_*").contains("matches no selection"));
    }

    #[test]
    fn a_count_that_can_never_be_reached_is_an_error() {
        assert_eq!(
            error("4 of selection*"),
            "the condition needs 4 of \"selection*\", which matches 3 selections"
        );
        assert!(error("0 of them").contains("needs 0 of"));
        assert!(error("some of them").contains("use a number or \"all\""));
    }

    #[test]
    fn an_unknown_selection_is_an_error() {
        assert_eq!(
            error("selection_a and missing"),
            "the condition names the selection \"missing\", which the rule does not have"
        );
    }

    #[test]
    fn syntax_errors_name_the_problem() {
        assert_eq!(error(""), "the condition is empty");
        assert_eq!(error("   "), "the condition is empty");
        assert_eq!(
            error("selection_a and"),
            "the condition ends where a selection must be"
        );
        assert_eq!(
            error("(selection_a"),
            "the condition has a \"(\" with no \")\""
        );
        assert_eq!(
            error("selection_a)"),
            "the condition has a \")\" with no \"(\""
        );
        assert_eq!(
            error("()"),
            "the condition has a \")\" where a selection must be"
        );
        assert_eq!(
            error("selection_a selection_b"),
            "the condition has \"selection_b\" where \"and\" or \"or\" must be"
        );
        assert_eq!(
            error("selection_a (filter)"),
            "the condition has a \"(\" where \"and\" or \"or\" must be"
        );
        assert_eq!(
            error("and selection_a"),
            "the condition has \"and\" where a selection must be"
        );
        assert_eq!(
            error("1 of"),
            "the condition has \"of\" with no selection pattern after it"
        );
        assert!(error("selection_a | count() > 5").contains("aggregation is not supported"));
    }

    #[test]
    fn deep_nesting_is_an_error_and_not_a_stack_overflow() {
        let depth = 5_000;
        let text = format!("{}selection_a{}", "(".repeat(depth), ")".repeat(depth));
        assert_eq!(error(&text), "the condition nests deeper than 32 levels");
        let text = format!("{}selection_a", "not ".repeat(depth));
        assert_eq!(error(&text), "the condition nests deeper than 32 levels");
        let allowed = format!("{}selection_a{}", "(".repeat(32), ")".repeat(32));
        assert!(evaluate(&allowed, [T, F, F, F]));
    }
}
