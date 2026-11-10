//! ISO codes and display names from the public-domain IANA tzdb table.
const COMMON: &[(&str, &str)] = &[
    ("US", "United States"),
    ("JP", "Japan"),
    ("CA", "Canada"),
    ("GB", "United Kingdom"),
    ("DE", "Germany"),
    ("SG", "Singapore"),
    ("AU", "Australia"),
    ("FR", "France"),
    ("NL", "Netherlands"),
    ("CH", "Switzerland"),
    ("KR", "South Korea"),
    ("TW", "Taiwan"),
    ("HK", "Hong Kong"),
];

pub fn choices() -> impl Iterator<Item = (&'static str, &'static str)> {
    COMMON.iter().copied().chain(
        include_str!("iso3166.tab")
            .lines()
            .filter(|line| !line.starts_with('#'))
            .filter_map(|line| line.split_once('\t'))
            .filter(|(code, _)| *code != "CN" && !COMMON.iter().any(|(common, _)| common == code)),
    )
}

pub fn name(code: &str) -> Option<&'static str> {
    choices().find_map(|(candidate, name)| (candidate == code).then_some(name))
}
