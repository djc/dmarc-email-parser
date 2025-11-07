use std::{
    io::{self, Read},
    net::IpAddr,
};

use anyhow::Error;
use instant_xml::FromXml;

pub fn mail_to_report(bytes: &[u8]) -> anyhow::Result<Feedback> {
    let mail = mailparse::parse_mail(bytes)?;

    let (ctype, body) = match mail.subparts.is_empty() {
        true => (&mail.ctype, mail.get_body_raw()),
        false => mail
            .subparts
            .iter()
            .filter_map(|part| match part.ctype.mimetype.as_ref() {
                "multipart/related" => None,
                _ => Some((&part.ctype, part.get_body_raw())),
            })
            .next()
            .ok_or(Error::msg("no content part found"))?,
    };

    let body = body?;
    let reader = io::Cursor::new(&body);
    let mut buf = Vec::new();
    match ctype.mimetype.as_str() {
        "text/plain" => buf = body,
        "application/zip" => {
            let mut archive = zip::ZipArchive::new(reader)?;
            if archive.len() > 1 {
                return Err(Error::msg(format!(
                    "too many files in archive ({})",
                    archive.len()
                )));
            }

            let mut file = archive.by_index(0)?;
            file.read_to_end(&mut buf)?;
        }
        "application/gzip" => {
            let mut decoder = flate2::read::GzDecoder::new(reader);
            decoder.read_to_end(&mut buf)?;
        }
        type_str => {
            if type_str.starts_with("text/") {
                let s = String::from_utf8(body)?;
                println!("{s}");
            }

            return Err(Error::msg(format!(
                "unsupported content type: {}",
                ctype.mimetype
            )));
        }
    }

    let s = String::from_utf8(buf)?;
    Ok(instant_xml::from_str(&s)?)
}

#[derive(Debug, FromXml)]
#[xml(rename = "feedback")]
pub struct Feedback {
    pub version: String,
    pub report_metadata: ReportMetadata,
    pub policy_published: PolicyPublished,
    pub records: Vec<Record>,
}

#[derive(Debug, FromXml)]
#[xml(rename = "report_metadata")]
pub struct ReportMetadata {
    pub org_name: String,
    pub email: String,
    pub extra_contact_info: Option<String>,
    pub report_id: String,
    pub date_range: DateRange,
    #[xml(rename = "error")]
    pub errors: Vec<String>,
}

#[derive(Debug, FromXml)]
#[xml(rename = "policy_published")]
pub struct PolicyPublished {
    pub domain: String,
    /// DKIM alignment
    pub adkim: Option<Alignment>,
    /// SPF alignment
    pub aspf: Option<Alignment>,
    /// Overall policy
    pub p: Disposition,
    /// Subdomain policy
    pub sp: Disposition,
    pub pct: u8,
    /// Failure reporting options
    pub fo: Option<String>,
}

#[derive(Clone, Copy, Debug, FromXml, PartialEq)]
#[xml(scalar)]
pub enum Alignment {
    #[xml(rename = "r")]
    Relaxed,
    #[xml(rename = "s")]
    Strict,
}

#[derive(Debug, FromXml)]
#[xml(rename = "record")]
pub struct Record {
    pub row: Row,
    pub identifiers: Identifiers,
    pub auth_results: AuthResults,
}

#[derive(Debug, FromXml)]
#[xml(rename = "row")]
pub struct Row {
    pub source_ip: IpAddr,
    pub count: u32,
    pub policy_evaluated: PolicyEvaluated,
}

#[derive(Debug, FromXml)]
#[xml(rename = "policy_evaluated")]
pub struct PolicyEvaluated {
    pub disposition: Disposition,
    pub dkim: DmarcResult,
    pub spf: DmarcResult,
}

#[derive(Clone, Copy, Debug, FromXml, PartialEq)]
#[xml(scalar)]
pub enum Disposition {
    #[xml(rename = "none")]
    None,
    #[xml(rename = "quarantine")]
    Quarantine,
    #[xml(rename = "reject")]
    Reject,
}

#[derive(Clone, Copy, Debug, FromXml, PartialEq)]
#[xml(scalar)]
pub enum DmarcResult {
    #[xml(rename = "pass")]
    Pass,
    #[xml(rename = "fail")]
    Fail,
}

#[derive(Debug, FromXml)]
#[xml(rename = "identifiers")]
pub struct Identifiers {
    pub envelope_to: Option<String>,
    pub envelope_from: Option<String>,
    pub header_from: String,
}

#[derive(Debug, FromXml)]
#[xml(rename = "auth_results")]
pub struct AuthResults {
    pub dkim: Option<DkimAuthResult>,
    pub spf: Option<SpfAuthResult>,
}

#[derive(Debug, FromXml)]
#[xml(rename = "dkim")]
pub struct DkimAuthResult {
    pub domain: String,
    pub result: DkimResult,
}

#[derive(Clone, Copy, Debug, FromXml, PartialEq)]
#[xml(scalar)]
pub enum DkimResult {
    #[xml(rename = "none")]
    None,
    #[xml(rename = "pass")]
    Pass,
    #[xml(rename = "fail")]
    Fail,
    #[xml(rename = "policy")]
    Policy,
    #[xml(rename = "neutral")]
    Neutral,
    #[xml(rename = "temperror")]
    TempError,
    #[xml(rename = "permerror")]
    PermError,
}

#[derive(Debug, FromXml)]
#[xml(rename = "spf")]
pub struct SpfAuthResult {
    pub domain: String,
    pub result: SpfResult,
}

#[derive(Clone, Copy, Debug, FromXml, PartialEq)]
#[xml(scalar)]
pub enum SpfResult {
    #[xml(rename = "none")]
    None,
    #[xml(rename = "neutral")]
    Neutral,
    #[xml(rename = "pass")]
    Pass,
    #[xml(rename = "fail")]
    Fail,
    #[xml(rename = "softfail")]
    SoftFail,
    #[xml(rename = "temperror")]
    TempError,
    #[xml(rename = "permerror")]
    PermError,
}

#[derive(Debug, FromXml)]
#[xml(rename = "date_range")]
pub struct DateRange {
    pub begin: u64,
    pub end: u64,
}
