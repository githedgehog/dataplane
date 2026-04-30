// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Filter setup for filtering outputs

use colored::Colorize;
use regex::Regex;
use std::str::SplitWhitespace;

#[derive(Debug, PartialEq)]
pub enum FilterCode {
    Only,
    Not,
    HighLight,
}
impl TryFrom<&str> for FilterCode {
    type Error = &'static str;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "only" => Ok(FilterCode::Only),
            "not" => Ok(FilterCode::Not),
            "high" => Ok(FilterCode::HighLight),
            _ => Err("Unknown filter"),
        }
    }
}

#[derive(Debug)]
pub struct Filter {
    code: FilterCode,
    tokens: Vec<String>,
}
impl Filter {
    fn from_code(code: FilterCode) -> Self {
        Self {
            code,
            tokens: Vec::new(),
        }
    }
    fn add_token(&mut self, token: &str) {
        self.tokens.push(token.to_owned());
    }
}

pub const PIPE: &str = "|";
pub const HEADING_CHAR: char = '━';

fn highlight(line: &str, re: &Regex) -> String {
    let mut result = String::new();
    let mut last = 0;

    for m in re.find_iter(line) {
        result.push_str(&line[last..m.start()]);
        result.push_str(&m.as_str().red().bold().to_string());
        last = m.end();
    }

    result.push_str(&line[last..]);
    result
}

pub fn parse_filters(
    mut split: SplitWhitespace<'_>,
    filters: &mut Vec<Filter>,
) -> Result<(), &'static str> {
    loop {
        let Some(keyword) = split.next() else {
            return Err("Missing filter");
        };
        // build filter from code
        let mut filter = Filter::from_code(FilterCode::try_from(keyword)?);
        let mut more_filters = false;
        for word in split.by_ref() {
            if word == PIPE {
                // new filter begins. Store the current one and parse the next
                more_filters = true;
                break;
            }
            filter.add_token(word);
        }
        if filter.tokens.is_empty() {
            return Err("Missing filter token");
        }
        filters.push(filter);
        if !more_filters {
            return Ok(());
        }
    }
}

// Filter some output based on the given filters
pub fn filter_output(output: &str, filters: &Vec<Filter>) -> String {
    if filters.is_empty() {
        return output.to_string();
    }

    // Highlighting does not affect what is output and can be executed last,
    // collecting all of the patterns to highlight into a single regex.
    let patterns: Vec<String> = filters
        .iter()
        .filter(|filter| matches!(filter.code, FilterCode::HighLight))
        .flat_map(|filter| filter.tokens.iter().map(String::as_str).map(regex::escape))
        .collect();

    let high_regex = if patterns.is_empty() {
        None
    } else {
        Regex::new(&patterns.join("|")).ok()
    };

    let lines: Vec<String> = output
        .lines()
        .filter_map(|line| {
            // line is each of the lines we are about to process. For each line, we
            // need to tell if it must be output or not and how. `Include` below is
            // per line and must be true in the last filter for the line to be shown.
            let mut include = true;
            if line.contains(HEADING_CHAR) {
                return Some(line.to_string());
            }

            // apply the filters in order for each of the lines
            for filter in filters {
                match filter.code {
                    FilterCode::Only => {
                        if include {
                            include = filter.tokens.iter().any(|w| line.contains(w));
                        }
                    }
                    FilterCode::Not => {
                        if include {
                            include = !filter.tokens.iter().any(|w| line.contains(w));
                        }
                    }
                    FilterCode::HighLight => {
                        // handled last after applying all filters so that it is
                        // applied once and only for the lines that should be output, with a single
                        // regex that includes all patterns
                    }
                }
            }
            if !include {
                return None;
            }
            match &high_regex {
                Some(re) => Some(highlight(line, re)),
                None => Some(line.to_string()),
            }
        })
        .collect();

    lines.join("\n")
}

#[cfg(test)]
mod test {
    use super::FilterCode;
    use super::filter_output;
    use crate::terminal::Terminal;

    #[test]
    fn test_setup_filter() {
        // test that filters are setup from user input
        let user_input = "show ip route | only foo bar baz | not bad ugly | high AAAA";
        let terminput = Terminal::proc_line(user_input).unwrap();
        let filters = terminput.get_filters();
        assert_eq!(filters.len(), 3);

        // only foo bar baz
        let filter_0 = &filters[0];
        assert_eq!(filter_0.code, FilterCode::Only);
        assert_eq!(filter_0.tokens.len(), 3);
        assert!(filter_0.tokens.contains(&"foo".to_string()));
        assert!(filter_0.tokens.contains(&"bar".to_string()));
        assert!(filter_0.tokens.contains(&"baz".to_string()));

        // not bad ugly
        let filter_1 = &filters[1];
        assert_eq!(filter_1.code, FilterCode::Not);
        assert_eq!(filter_1.tokens.len(), 2);
        assert!(filter_1.tokens.contains(&"bad".to_string()));
        assert!(filter_1.tokens.contains(&"ugly".to_string()));

        // high AAAA
        let filter_2 = &filters[2];
        assert_eq!(filter_2.code, FilterCode::HighLight);
        assert_eq!(filter_2.tokens.len(), 1);
        assert!(filter_2.tokens.contains(&"AAAA".to_string()));
    }

    #[test]
    fn test_output_filter() {
        let user_input =
            "somecommand | only 192.168.1.1/32 192.168.2.0 | high Hedgehog | not porcupine lion";
        let terminput = Terminal::proc_line(user_input).unwrap();

        let output = "
1 SHOWN 192.168.1.1/32 Hedgehog
2 NO-SHOW porcupine
3 NO-SHOW 192.168.3.0
4 NO-SHOW 192.168.1.1/32 lion
5 SHOWN My address is 192.168.2.0
";
        let output = filter_output(output, terminput.get_filters());
        println!("{output}");
        assert!(output.contains("SHOWN"));
        assert!(!output.contains("NO-SHOW"));
    }
}
