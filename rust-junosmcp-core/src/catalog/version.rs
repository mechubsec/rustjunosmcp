//! Family and Release train detection from a device's model and version string.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::JmcpError;

/// The Juniper schema lineage a device belongs to (see `GLOSSARY.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Family {
    /// SRX, vSRX and cSRX on Junos OS.
    JunosEs,
    /// EX switches on Junos OS.
    JunosEx,
    /// Devices running Junos OS Evolved.
    JunosEvo,
}

impl Family {
    /// Every Family, in catalog slot order.
    pub const ALL: [Family; 3] = [Family::JunosEs, Family::JunosEx, Family::JunosEvo];

    /// The catalog name: `"junos-es"`, `"junos-ex"` or `"junos-evo"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Family::JunosEs => "junos-es",
            Family::JunosEx => "junos-ex",
            Family::JunosEvo => "junos-evo",
        }
    }
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Family {
    type Err = JmcpError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Family::ALL
            .into_iter()
            .find(|family| family.as_str().eq_ignore_ascii_case(name.trim()))
            .ok_or_else(|| {
                JmcpError::Validation(format!(
                    "unknown family {name:?}; expected junos-es, junos-ex or junos-evo"
                ))
            })
    }
}

/// A `major.minor` Junos Release train, such as `23.4`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Train {
    /// The major release, `23` in `23.4`.
    pub major: u16,
    /// The minor release, `4` in `23.4`.
    pub minor: u16,
}

/// The oldest train the catalog supports.
const LOWEST_SUPPORTED: Train = Train {
    major: 23,
    minor: 1,
};

impl fmt::Display for Train {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl FromStr for Train {
    type Err = JmcpError;

    /// Parses a bare train (`"23.4"`); use [`train_for`] for full version strings.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || JmcpError::Validation(format!("invalid release train {text:?}"));
        let (major, minor) = text.trim().split_once('.').ok_or_else(invalid)?;
        Ok(Train {
            major: major.parse().map_err(|_| invalid())?,
            minor: minor.parse().map_err(|_| invalid())?,
        })
    }
}

impl Serialize for Train {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Train {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// The Release train of a Junos version string (`"23.4R2-S2.1"` → `23.4`,
/// `"25.4X300-D40.2-EVO"` → `25.4`).
///
/// Returns `None` for an unparseable string or a train below 23.1.
pub fn train_for(version: &str) -> Option<Train> {
    let (major, rest) = version.trim().split_once('.')?;
    let minor_len = rest
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(rest.len());
    let train = Train {
        major: major.parse().ok()?,
        minor: rest[..minor_len].parse().ok()?,
    };
    (train >= LOWEST_SUPPORTED).then_some(train)
}

/// Why an SRX on Junos OS Evolved is answered inexactly.
pub const SRX_EVO_WARNING: &str =
    "SRX on Junos OS Evolved: Juniper publishes no SRX EVO YANG; answered from junos-es";

/// The Family of a device from its reported model and version, and whether
/// that Family is exact for the device.
///
/// SRX, vSRX and cSRX models are `junos-es`; on a `-EVO` release that is
/// inexact (see [`SRX_EVO_WARNING`]). Any other `-EVO` version is
/// `junos-evo`, EX models `junos-ex`. Anything else returns `None`.
pub fn family_for(model: &str, version: &str) -> Option<(Family, bool)> {
    let evo = version.to_ascii_uppercase().contains("-EVO");
    let model = model.trim().to_ascii_lowercase();
    if ["srx", "vsrx", "csrx"]
        .iter()
        .any(|prefix| model.starts_with(prefix))
    {
        return Some((Family::JunosEs, !evo));
    }
    if evo {
        return Some((Family::JunosEvo, true));
    }
    if model.starts_with("ex") {
        return Some((Family::JunosEx, true));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn train(major: u16, minor: u16) -> Train {
        Train { major, minor }
    }

    #[test]
    fn train_for_table() {
        let cases = [
            ("23.4R2-S2.1", Some(train(23, 4))),
            ("25.4R1.12", Some(train(25, 4))),
            ("25.4X300-D40.2-EVO", Some(train(25, 4))),
            ("26.2R1.7", Some(train(26, 2))),
            ("24.2R2-S5.5", Some(train(24, 2))),
            ("23.1R1", Some(train(23, 1))),
            ("22.4R3", None),
            ("15.1X49-D200", None),
            ("", None),
            ("junos", None),
            ("23.", None),
        ];
        for (version, expected) in cases {
            assert_eq!(train_for(version), expected, "{version:?}");
        }
    }

    #[test]
    fn family_for_table() {
        let cases = [
            (
                "SRX440",
                "25.4X300-D40.2-EVO",
                Some((Family::JunosEs, false)),
            ),
            ("PTX10001", "25.4R1.9-EVO", Some((Family::JunosEvo, true))),
            ("EX2300-C-12P", "23.4R2-S2.1", Some((Family::JunosEx, true))),
            ("csrx", "26.2R1.7", Some((Family::JunosEs, true))),
            ("cSRX", "26.2R1.7", Some((Family::JunosEs, true))),
            ("vSRX3", "24.2R2-S5.5", Some((Family::JunosEs, true))),
            ("SRX345", "23.4R2", Some((Family::JunosEs, true))),
            ("MX204", "23.4R1", None),
        ];
        for (model, version, expected) in cases {
            assert_eq!(family_for(model, version), expected, "{model} {version}");
        }
    }

    #[test]
    fn family_and_train_round_trip() {
        for family in Family::ALL {
            assert_eq!(family.as_str().parse::<Family>().unwrap(), family);
        }
        assert!("junos-qfx".parse::<Family>().is_err());
        assert_eq!(train(23, 4).to_string(), "23.4");
        assert_eq!("23.4".parse::<Train>().unwrap(), train(23, 4));
        assert_eq!(
            serde_json::to_string(&Family::JunosEvo).unwrap(),
            "\"junos-evo\""
        );
    }
}
