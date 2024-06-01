use clap::Parser;

mod server;
use server::{ startable, http_server };

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
   #[arg(long)]
   config_file: String
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let srv_conf_doc = read_config(&args.config_file.to_string());
    let httpd = http_server::start(srv_conf_doc.as_str());
}

fn read_config(config_file_path: &str) -> String {
  let file_content = std::fs::read(config_file_path).expect("File does not exist or is corrupted.");
  let return_value = std::str::from_utf8(&file_content).expect("File is corrupted.");
  return_value.to_string()
}