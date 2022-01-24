use std::borrow::Cow;
use std::io::{self, Read};

use thiserror::Error;

pub fn mail_to_report(
    bytes: &[u8],
) -> Result<dmarc_aggregate_parser::aggregate_report::feedback, Error> {
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
            .ok_or("no content part found")?,
    };

    let body = body?;
    let reader = io::Cursor::new(&body);
    let mut buf = Vec::new();
    match ctype.mimetype.as_str() {
        "application/zip" => {
            let mut archive = zip::ZipArchive::new(reader)?;
            if archive.len() > 1 {
                return Err(format!("too many files in archive ({})", archive.len()).into());
            }

            let mut file = archive.by_index(0)?;
            file.read_to_end(&mut buf)?;
        }
        "application/gzip" => {
            let mut decoder = flate2::read::GzDecoder::new(reader);
            decoder.read_to_end(&mut buf)?;
        }
        _ => return Err(format!("unsupported content type: {}", ctype.mimetype).into()),
    }

    dmarc_aggregate_parser::parse_reader(&mut io::Cursor::new(&buf))
        .map_err(|e| format!("{}", e).into())
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Custom(Cow<'static, str>),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("error parsing email: {0}")]
    Parse(#[from] mailparse::MailParseError),
    #[error("error from zip decompression: {0}")]
    Zip(#[from] zip::result::ZipError),
}

impl From<&'static str> for Error {
    fn from(s: &'static str) -> Self {
        Error::Custom(s.into())
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Custom(s.into())
    }
}
