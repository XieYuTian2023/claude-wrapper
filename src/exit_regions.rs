//! ISO codes and display names from the public-domain IANA tzdb table.
const COMMON: &[(&str, &str)] = &[
    ("US", "美国 / United States"),
    ("JP", "日本 / Japan"),
    ("CA", "加拿大 / Canada"),
    ("GB", "英国 / United Kingdom"),
    ("DE", "德国 / Germany"),
    ("SG", "新加坡 / Singapore"),
    ("AU", "澳大利亚 / Australia"),
    ("FR", "法国 / France"),
    ("NL", "荷兰 / Netherlands"),
    ("CH", "瑞士 / Switzerland"),
    ("KR", "韩国 / South Korea"),
    ("TW", "台湾 / Taiwan"),
    ("HK", "香港 / Hong Kong"),
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
