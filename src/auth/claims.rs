use serde_json::Value;

use super::Claims;
use crate::config::{ClaimCheck, ClaimRule};

/// Evaluates every rule; returns a description of the first one that fails.
pub fn check_claims(claims: &Claims, rules: &[ClaimRule]) -> Result<(), String> {
    for rule in rules {
        let value = lookup(claims, &rule.claim);
        let ok = match (&rule.check, value) {
            (ClaimCheck::Exists(want), v) => v.is_some() == *want,
            (_, None) => false,
            (ClaimCheck::Equals(want), Some(v)) => v == want,
            (ClaimCheck::OneOf(options), Some(v)) => options.contains(v),
            (ClaimCheck::Contains(item), Some(Value::Array(items))) => {
                items.iter().any(|i| i.as_str() == Some(item.as_str()))
            }
            (ClaimCheck::Contains(item), Some(Value::String(s))) => {
                s.split_ascii_whitespace().any(|t| t == item)
            }
            (ClaimCheck::Contains(_), Some(_)) => false,
        };
        if !ok {
            return Err(format!("claim {:?} does not satisfy policy", rule.claim));
        }
    }
    Ok(())
}

fn lookup<'a>(claims: &'a Claims, path: &str) -> Option<&'a Value> {
    let mut parts = path.split('.');
    let mut cur = claims.get(parts.next()?)?;
    for p in parts {
        cur = cur.as_object()?.get(p)?;
    }
    Some(cur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rule(claim: &str, check: ClaimCheck) -> ClaimRule {
        ClaimRule {
            claim: claim.into(),
            check,
        }
    }

    fn claims() -> Claims {
        json!({
            "sub": "user-1",
            "scope": "orders:read orders:write",
            "roles": ["admin", "billing"],
            "realm": { "tier": "gold" },
            "email_verified": true
        })
        .as_object()
        .unwrap()
        .clone()
    }

    #[test]
    fn passing_rules() {
        let rules = vec![
            rule("scope", ClaimCheck::Contains("orders:read".into())),
            rule("roles", ClaimCheck::Contains("billing".into())),
            rule(
                "realm.tier",
                ClaimCheck::OneOf(vec![json!("gold"), json!("platinum")]),
            ),
            rule("email_verified", ClaimCheck::Equals(json!(true))),
            rule("sub", ClaimCheck::Exists(true)),
            rule("impersonator", ClaimCheck::Exists(false)),
        ];
        assert_eq!(check_claims(&claims(), &rules), Ok(()));
    }

    #[test]
    fn failing_rules() {
        let c = claims();
        for r in [
            rule("scope", ClaimCheck::Contains("orders".into())),
            rule("roles", ClaimCheck::Contains("root".into())),
            rule("realm.tier", ClaimCheck::Equals(json!("silver"))),
            rule("realm.missing", ClaimCheck::Exists(true)),
            rule("sub", ClaimCheck::Exists(false)),
            rule("email_verified", ClaimCheck::Contains("true".into())),
        ] {
            assert!(
                check_claims(&c, std::slice::from_ref(&r)).is_err(),
                "{r:?} should fail"
            );
        }
    }
}
