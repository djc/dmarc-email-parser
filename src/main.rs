use std::fs;
use std::path::PathBuf;

use clap::Parser;
use hickory_resolver::TokioResolver;
use time::{OffsetDateTime, format_description};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
    let format = format_description::parse("[month repr:short] [day], [hour]:[minute]").unwrap();
    let resolver = TokioResolver::builder_tokio()?.build();

    let mut files = Vec::new();
    for entry in fs::read_dir(&opts.path).unwrap() {
        match entry {
            Ok(entry) => files.push(entry.path()),
            Err(error) => {
                println!("failed to read entry: {error:#?}");
                continue;
            }
        }
    }

    files.sort_unstable();
    for path in files.into_iter().rev() {
        let raw = match fs::read(&path) {
            Ok(raw) => raw,
            Err(error) => {
                println!("failed to read file {}: {error:#?}", path.display());
                continue;
            }
        };

        if let Some(filename) = path.file_name() {
            println!("reading from file: {}", filename.display());
        }

        let feedback = match dmarc_email_parser::mail_to_report(&raw) {
            Ok(feedback) => feedback,
            Err(error) => {
                println!(
                    "failed to parse DMARC report from file {}: {error:#?}",
                    path.display()
                );
                continue;
            }
        };

        let start =
            OffsetDateTime::from_unix_timestamp(feedback.report_metadata.date_range.begin as i64)?;
        let end =
            OffsetDateTime::from_unix_timestamp(feedback.report_metadata.date_range.end as i64)?;

        println!(
            "Report from {} from {} until {}:",
            feedback.report_metadata.org_name,
            start.format(&format)?,
            end.format(&format)?,
        );

        for error in feedback.report_metadata.errors {
            println!("error: {}", error);
        }

        for record in feedback.records {
            let host = match resolver.reverse_lookup(record.row.source_ip).await {
                Ok(lookup) => match lookup.iter().next() {
                    Some(name) => name.0.to_string(),
                    None => "N/A".to_owned(),
                },
                _ => "N/A".to_owned(),
            };

            println!(
                "{} messages from {} via {} ({host})",
                record.row.count, record.identifiers.header_from, record.row.source_ip
            );
            println!(
                "  disposition: {:?}, DKIM: {:?}, SPF: {:?}",
                record.row.policy_evaluated.disposition,
                record.row.policy_evaluated.dkim,
                record.row.policy_evaluated.spf
            );

            match record.auth_results.dkim {
                Some(dkim) => println!("  DKIM: {:?} ({})", dkim.result, dkim.domain),
                None => println!("  DKIM: no results"),
            }

            match record.auth_results.spf {
                Some(spf) => println!("  SPF: {:?} ({})", spf.result, spf.domain),
                None => println!("  SPF: no results"),
            }
        }
        println!();

        if opts.remove {
            fs::remove_file(path)?;
        }
    }

    Ok(())
}

#[derive(Debug, Parser)]
struct Opts {
    path: PathBuf,
    #[clap(long, default_value = "false")]
    remove: bool,
}
