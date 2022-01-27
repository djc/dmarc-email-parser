use std::fs;
use std::path::PathBuf;

use clap::Parser;
use dmarc_aggregate_parser::aggregate_report::DMARCResultType;
use time::{format_description, OffsetDateTime};

fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
    for entry in fs::read_dir(&opts.path).unwrap() {
        let entry = entry?;
        let raw = fs::read(entry.path())?;
        let feedback = dmarc_email_parser::mail_to_report(&raw)?;

        let mut failed = Vec::new();
        for record in feedback.record {
            #[allow(clippy::if_same_then_else)]
            if let Some(DMARCResultType::fail) = record.row.policy_evaluated.dkim {
                failed.push(record);
            } else if let Some(DMARCResultType::fail) = record.row.policy_evaluated.spf {
                failed.push(record);
            }
        }

        if failed.is_empty() && feedback.report_metadata.error.is_none() {
            fs::remove_file(entry.path())?;
            continue;
        }

        let format =
            format_description::parse("[month repr:short] [day], [hour]:[minute]").unwrap();
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

        if let Some(errors) = &feedback.report_metadata.error {
            for error in errors {
                println!("error: {}", error);
            }
        }

        for record in failed {
            println!("{:#?}", record);
        }
        println!();

        fs::remove_file(entry.path())?;
    }

    Ok(())
}

#[derive(Debug, Parser)]
struct Opts {
    path: PathBuf,
}
