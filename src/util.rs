use std::{net::Ipv4Addr, str::FromStr, sync::Arc};

use ahash::RandomState;
use config::Config;
use fern::{
    colors::{Color, ColoredLevelConfig},
    Dispatch,
};
use moka::future::Cache;

use log::{debug, error};
use tonic::{metadata::MetadataValue, Request, Status};

use crate::{database::Database, error::ProxyCheckError};

pub fn check_auth(token: &String, req: Request<()>) -> Result<Request<()>, Status> {
    let token: MetadataValue<_> = match format!("Bearer {}", token).parse() {
        Ok(meta) => meta,
        Err(err) => {
            error!("Failed to parse authorization token: {}", err);
            return Err(Status::unauthenticated("No valid auth token"));
        }
    };

    match req.metadata().get("authorization") {
        Some(t) if token.eq(t) => Ok(req),
        _ => Err(Status::unauthenticated("No valid auth token")),
    }
}

pub fn init_logger() {
    let colors_level = ColoredLevelConfig::new()
        .error(Color::Red)
        .warn(Color::Yellow)
        .info(Color::Blue)
        .debug(Color::Yellow);

    match Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{date} {level}\x1B[0m {message}",
                date = chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                level = colors_level.color(record.level()),
                message = message,
            ));
        })
        .level(log::LevelFilter::Info)
        .chain(std::io::stdout())
        .apply()
    {
        Ok(_) => (),
        Err(err) => panic!("Failed to set up error logging: {}", err),
    };
}

pub async fn using_vpn(
    config: Arc<Config>,
    cache: Cache<[u8; 4], bool, RandomState>,
    database: Database,
    ip: &String,
) -> Result<bool, ProxyCheckError> {
    let ip = match Ipv4Addr::from_str(ip) {
        Ok(ip) => ip,
        Err(err) => {
            error!("Failed to parse address {}: {}", ip, err);
            return Err(ProxyCheckError);
        }
    };

    if let Some(result) = cache.get(&ip.octets()) {
        debug!("Using cached result for {}: {}", &ip.to_string(), result);
        return Ok(result);
    }

    match database.whitelist_check(ip.octets()).await {
        Ok(_) => {
            cache.insert(ip.octets(), false).await;
            return Ok(false);
        }
        Err(err) => {
            if !matches!(err, sqlx::Error::RowNotFound) {
                error!(
                    "Error running whitelist check for {}: {}",
                    ip.to_string(),
                    err
                );
                return Err(ProxyCheckError);
            }
        }
    }

    let request_url = format!(
        "http://proxycheck.io/v2/{ip}?key={key}&vpn=1",
        ip = ip.to_string(),
        key = config.get_string("vpn").unwrap(),
    );

    let response = match reqwest::get(&request_url).await {
        Ok(res) => res,
        Err(err) => {
            error!("Failed to make request for {}: {}", ip.to_string(), err);
            return Err(ProxyCheckError);
        }
    };

    let result: serde_json::Value = match response.json().await {
        Ok(res) => res,
        Err(err) => {
            error!("Failed to parse JSON for {}: {}", ip.to_string(), err);
            return Err(ProxyCheckError);
        }
    };

    debug!("{:?}", result);

    if result["status"].eq("ok") {
        debug!("Inserting cache for {}: {}", ip.to_string(), result);
        cache
            .insert(ip.octets(), result[ip.to_string()]["proxy"].eq("yes"))
            .await;
        Ok(result[ip.to_string()]["proxy"].eq("yes"))
    } else {
        Err(ProxyCheckError)
    }
}
