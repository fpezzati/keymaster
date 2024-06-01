use clap::builder::Str;

pub trait startable {
    fn start(config: &str) -> Self;
}

pub struct http_server {
    host: String,
    port: String,
    public_key: String,
    private_key: String,
    pub oauth2_conf: String
}

impl startable for http_server {
    fn start(config: &str) -> Self {
        println!("{}", config);
        http_server {
            host: String::new(), port: String::new(), public_key: String::new(), private_key: String::new(), oauth2_conf: String::new()
        }
    }
}