mod cli;
mod config;
mod crypto;
mod integrity;
mod monitors;

fn main() {
    tracing_subscriber::fmt::init();
    let cmd = clap::Command::new("cerberus")
        .subcommand_required(true)
        .subcommand(
        clap::command!("gen-config")
            .about("Generate a signed configuration file for production deployment")
            .arg(
                clap::arg!(-k --"key-path" <FILE> "a config signing key file path")
                    .required(true)
                    .value_parser(clap::value_parser!(std::path::PathBuf)),
            )
            .arg(
                clap::arg!(-c --"config-path" <FILE> "the input config file path")
                    .required(true)
                    .value_parser(clap::value_parser!(std::path::PathBuf)),
            )
            .arg(
                clap::arg!(-o --"output-path" <FILE> "the output file path for the signed config")
                    .required(true)
                    .value_parser(clap::value_parser!(std::path::PathBuf)),
            ),
    ).subcommand(
        clap::command!("test-config")
            .about("Test a signed configuration file for validity")
            .arg(
                clap::arg!(-c --config <FILE> "the signed config file to test")
                    .required(true)
                    .value_parser(clap::value_parser!(std::path::PathBuf)),
            ),
    );
    let matches = cmd.get_matches();
    match matches.subcommand() {
        Some(("gen-config", matches)) => {
            cli::config::gen_config(
                matches
                    .get_one::<std::path::PathBuf>("key-path")
                    .unwrap()
                    .as_path(),
                matches
                    .get_one::<std::path::PathBuf>("config-path")
                    .unwrap()
                    .as_path(),
                matches
                    .get_one::<std::path::PathBuf>("output-path")
                    .unwrap()
                    .as_path(),
            );
        }
        Some(("test-config", matches)) => {
            cli::config::test_config(
                matches
                    .get_one::<std::path::PathBuf>("config")
                    .unwrap()
                    .as_path(),
            );
        }
        _ => unreachable!("clap should ensure we don't get here"),
    };
}
