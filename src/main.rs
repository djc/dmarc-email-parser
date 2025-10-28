use std::fs;
use std::path::PathBuf;

use clap::Parser;
use time::{OffsetDateTime, format_description};

fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
    let format = format_description::parse("[month repr:short] [day], [hour]:[minute]").unwrap();

    for entry in fs::read_dir(&opts.path).unwrap() {
        let entry = entry?;
        let raw = fs::read(entry.path())?;
        let feedback = dmarc_email_parser::mail_to_report(&raw)?;

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
            println!(
                "{} messages from {}",
                record.row.count, record.row.source_ip
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
            fs::remove_file(entry.path())?;
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
