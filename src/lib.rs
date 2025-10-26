use std::io::{self, Read};

use anyhow::Error;

pub fn mail_to_report(
    bytes: &[u8],
) -> anyhow::Result<dmarc_aggregate_parser::aggregate_report::feedback> {
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
        _ => {
            return Err(Error::msg(format!(
                "unsupported content type: {}",
                ctype.mimetype
            )))
        }
    }

    Ok(dmarc_aggregate_parser::parse_reader(&mut io::Cursor::new(
        &buf,
    ))?)
}
