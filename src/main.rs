pub mod core;
use std::env;

fn main() {
    let mut launch_args = env::args();
    match (launch_args.nth(1), launch_args.len()) {
        (Some(arg), 0) if arg == "-ver" => println!("\nSrrir v{}", env!("CARGO_PKG_VERSION")),
        (Some(arg), 0) if arg == "-h" || arg == "-help" => println!(
            "\nSrrir v{} using instuctions\n\n-h or -help  As the name implies, show the help for you.\n-s  Follow the instructions and start your amazing journey.\n-ver  Show the current program version.",
            env!("CARGO_PKG_VERSION")
        ),
        (Some(arg), 0) if arg == "-s" => core::core(),
        (_, _) => println!("\nUnknown parameters or too many parameters. Use -help or -h to get help."),
    }
}
