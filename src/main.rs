use ahash::RandomState;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use config::Config;
use log::{error, info};
use mimalloc::MiMalloc;
use moka::future::Cache;
use regex::Regex;
use reqwest::StatusCode;
use std::{net::SocketAddr, process::exit, str::FromStr, sync::Arc, time::Duration};
use tokio::signal;
use tonic::{transport::Server, Request, Response, Status};
use uuid::Uuid;

use mith::{
    database::{Database, Player},
    error::Error,
    proto::{
        auth_service_server::{AuthService, AuthServiceServer},
        AcknowledgeRequest, AcknowledgeResponse, ChangePasswordRequest, ChangePasswordResponse,
        ControlRequest, ControlResponse, LoginRequest, LoginResponse, RegisterRequest,
        RegisterResponse, RetrieveRequest, RetrieveResponse,
    },
    util::{check_auth, init_logger, using_vpn},
};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Debug)]
pub struct MithServer {
    database: Database,
    cache: Cache<[u8; 4], bool, RandomState>,
    config: Arc<Config>,
}

#[tonic::async_trait]
impl AuthService for MithServer {
    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<LoginResponse>, Status> {
        let remote_addr = match request.remote_addr() {
            Some(remote_addr) => remote_addr,
            None => {
                error!("Failed to retrieve remote address");
                return Ok(Response::new(LoginResponse {
                    success: false,
                    error: Error::Unspecified as i32,
                }));
            }
        };

        info!(
            "Received Login({}, {}) request from {}",
            request.get_ref().uuid,
            request.get_ref().ip,
            remote_addr.ip()
        );

        let using_vpn = match using_vpn(
            self.config.clone(),
            self.cache.clone(),
            &request.get_ref().ip,
        )
        .await
        {
            Ok(using_vpn) => using_vpn,
            Err(_) => {
                return Ok(Response::new(LoginResponse {
                    success: false,
                    error: Error::Unspecified as i32,
                }));
            }
        };

        if using_vpn {
            return Ok(Response::new(LoginResponse {
                success: false,
                error: Error::UsingVpn as i32,
            }));
        }

        let data = request.into_inner();
        let uuid = match Uuid::try_parse(&data.uuid) {
            Ok(uuid) => uuid,
            Err(err) => {
                error!("Error while parsing {} UUID: {}", data.uuid, err);
                return Ok(Response::new(LoginResponse {
                    success: false,
                    error: Error::Unspecified as i32,
                }));
            }
        };

        let mut player = match self.database.retrieve(uuid).await {
            Ok(player) => player,
            Err(err) => match err {
                sqlx::Error::RowNotFound => {
                    return Ok(Response::new(LoginResponse {
                        success: false,
                        error: Error::NotFound as i32,
                    }));
                }
                _ => {
                    error!(
                        "Error while retrieving data for {} UUID: {}",
                        data.uuid, err
                    );
                    return Ok(Response::new(LoginResponse {
                        success: false,
                        error: Error::Unspecified as i32,
                    }));
                }
            },
        };

        if player.locked {
            return Ok(Response::new(LoginResponse {
                success: false,
                error: Error::AccountLocked as i32,
            }));
        }

        let stored_password = match PasswordHash::new(&player.password) {
            Ok(pw) => pw,
            Err(err) => {
                error!(
                    "Failed to parse password hash for {}: {}",
                    &player.uuid, err
                );
                return Ok(Response::new(LoginResponse {
                    success: false,
                    error: Error::Unspecified as i32,
                }));
            }
        };

        let valid = Argon2::default()
            .verify_password(data.password.as_bytes(), &stored_password)
            .is_err();

        let mut old_valid = false;
        if let Some(ref old_password) = player.old_password {
            let old_password = match PasswordHash::new(&old_password) {
                Ok(pw) => pw,
                Err(err) => {
                    error!(
                        "Failed to parse password hash for {}: {}",
                        &player.uuid, err
                    );
                    return Ok(Response::new(LoginResponse {
                        success: false,
                        error: Error::Unspecified as i32,
                    }));
                }
            };

            old_valid = Argon2::default()
                .verify_password(data.password.as_bytes(), &old_password)
                .is_err();
        };

        if valid {
            if old_valid {
                player.update_locked(true);
                if let Err(err) = self.database.update_locked(player).await {
                    error!("Error while updating data for {} UUID: {}", data.uuid, err);
                    return Ok(Response::new(LoginResponse {
                        success: false,
                        error: Error::Unspecified as i32,
                    }));
                };
            }

            Ok(Response::new(LoginResponse {
                success: false,
                error: Error::AccountLocked as i32,
            }))
        } else {
            Ok(Response::new(LoginResponse {
                success: true,
                error: Error::Unspecified as i32,
            }))
        }
    }

    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let remote_addr = match request.remote_addr() {
            Some(remote_addr) => remote_addr,
            None => {
                error!("Failed to retrieve remote address");
                return Ok(Response::new(RegisterResponse {
                    success: false,
                    error: Error::Unspecified as i32,
                    security_code: "null".to_string(),
                }));
            }
        };

        info!(
            "Received Register({}, {}, {}) request from {}",
            request.get_ref().uuid,
            request.get_ref().username,
            request.get_ref().ip,
            remote_addr.ip()
        );

        let using_vpn = match using_vpn(
            self.config.clone(),
            self.cache.clone(),
            &request.get_ref().ip,
        )
        .await
        {
            Ok(using_vpn) => using_vpn,
            Err(err) => {
                error!(
                    "Failed to do VPN check for {} with IP {}: {}",
                    &request.get_ref().uuid,
                    &request.get_ref().ip,
                    err
                );
                return Ok(Response::new(RegisterResponse {
                    success: false,
                    error: Error::Unspecified as i32,
                    security_code: "null".to_string(),
                }));
            }
        };

        if using_vpn {
            return Ok(Response::new(RegisterResponse {
                success: false,
                error: Error::UsingVpn as i32,
                security_code: "null".to_string(),
            }));
        }

        let data = request.into_inner();

        let (player, security_code) =
            match Player::new(data.uuid.clone(), data.username, data.password) {
                Ok(res) => res,
                Err(err) => {
                    error!("Failed to create new player instance: {}", err);
                    return Ok(Response::new(RegisterResponse {
                        success: false,
                        error: Error::Unspecified as i32,
                        security_code: "null".to_string(),
                    }));
                }
            };

        if let Err(err) = self.database.insert(player).await {
            let database_error = match err.as_database_error() {
                Some(error) => error,
                None => {
                    error!("Failed outside database level: {}", err);
                    return Ok(Response::new(RegisterResponse {
                        success: false,
                        error: Error::Unspecified as i32,
                        security_code: "null".to_string(),
                    }));
                }
            };

            match database_error.code() {
                Some(error) => {
                    if error.to_string().eq("23000") {
                        return Ok(Response::new(RegisterResponse {
                            success: false,
                            error: Error::AlreadyExists as i32,
                            security_code: "null".to_string(),
                        }));
                    }
                }
                None => {
                    error!("Failed to get the database error code");
                    return Ok(Response::new(RegisterResponse {
                        success: false,
                        error: Error::Unspecified as i32,
                        security_code: "null".to_string(),
                    }));
                }
            };

            error!("Error while inserting data for {} UUID: {}", data.uuid, err);
            return Ok(Response::new(RegisterResponse {
                success: false,
                error: Error::Unspecified as i32,
                security_code: "null".to_string(),
            }));
        };

        Ok(Response::new(RegisterResponse {
            success: true,
            error: Error::Unspecified as i32,
            security_code,
        }))
    }

    async fn change_password(
        &self,
        request: Request<ChangePasswordRequest>,
    ) -> Result<Response<ChangePasswordResponse>, Status> {
        let remote_addr = match request.remote_addr() {
            Some(remote_addr) => remote_addr,
            None => {
                error!("Failed to retrieve remote address");
                return Ok(Response::new(ChangePasswordResponse {
                    success: false,
                    error: Error::Unspecified as i32,
                }));
            }
        };

        info!(
            "Received ChangePassword({}, {}) request from {}",
            request.get_ref().uuid,
            request.get_ref().ip,
            remote_addr.ip()
        );

        let data = request.into_inner();

        let uuid = match Uuid::try_parse(&data.uuid) {
            Ok(uuid) => uuid,
            Err(err) => {
                error!("Error while parsing {} UUID: {}", data.uuid, err);
                return Ok(Response::new(ChangePasswordResponse {
                    success: false,
                    error: Error::Unspecified as i32,
                }));
            }
        };

        let mut player = match self.database.retrieve(uuid).await {
            Ok(player) => player,
            Err(err) => match err {
                sqlx::Error::RowNotFound => {
                    return Ok(Response::new(ChangePasswordResponse {
                        success: false,
                        error: Error::NotFound as i32,
                    }));
                }
                _ => {
                    error!(
                        "Error while retrieving data for {} UUID: {}",
                        data.uuid, err
                    );
                    return Ok(Response::new(ChangePasswordResponse {
                        success: false,
                        error: Error::Unspecified as i32,
                    }));
                }
            },
        };

        let stored_password = match PasswordHash::new(&player.password) {
            Ok(hash) => hash,
            Err(err) => {
                error!(
                    "Failed to parse stored password hash for {}: {}",
                    &player.uuid, err
                );
                return Ok(Response::new(ChangePasswordResponse {
                    success: false,
                    error: Error::Unspecified as i32,
                }));
            }
        };

        let password = data.old_password.as_bytes();
        let valid = Argon2::default().verify_password(password, &stored_password);

        if valid.is_err() {
            return Ok(Response::new(ChangePasswordResponse {
                success: false,
                error: Error::InvalidPassword as i32,
            }));
        }

        if let Err(err) = player.update_password(data.new_password) {
            error!(
                "Error while updating password for {} UUID: {}",
                data.uuid, err
            );
            return Ok(Response::new(ChangePasswordResponse {
                success: false,
                error: Error::Unspecified as i32,
            }));
        };

        if let Err(err) = self.database.update_password(player).await {
            error!("Error while updating data for {} UUID: {}", data.uuid, err);
            return Ok(Response::new(ChangePasswordResponse {
                success: false,
                error: Error::Unspecified as i32,
            }));
        };

        Ok(Response::new(ChangePasswordResponse {
            success: true,
            error: Error::Unspecified as i32,
        }))
    }

    async fn acknowledge(
        &self,
        request: Request<AcknowledgeRequest>,
    ) -> Result<Response<AcknowledgeResponse>, Status> {
        let remote_addr = match request.remote_addr() {
            Some(remote_addr) => remote_addr,
            None => {
                error!("Failed to retrieve remote address");
                return Ok(Response::new(AcknowledgeResponse {
                    success: false,
                    error: Error::Unspecified as i32,
                }));
            }
        };

        info!(
            "Received Acknowledge({}) request from {}",
            request.get_ref().uuid,
            remote_addr.ip()
        );

        Ok(Response::new(AcknowledgeResponse {
            success: true,
            error: Error::Unspecified as i32,
        }))
    }

    async fn retrieve(
        &self,
        request: Request<RetrieveRequest>,
    ) -> Result<Response<RetrieveResponse>, Status> {
        let remote_addr = match request.remote_addr() {
            Some(remote_addr) => remote_addr,
            None => {
                error!("Failed to retrieve remote address");
                return Ok(Response::new(RetrieveResponse {
                    success: false,
                    premium: false,
                    error: Error::Unspecified as i32,
                }));
            }
        };

        info!(
            "Received Retrieve({}, {}) request from {}",
            request.get_ref().uuid,
            request.get_ref().username,
            remote_addr.ip()
        );

        let uuid = match Uuid::try_parse(&request.get_ref().uuid) {
            Ok(uuid) => uuid,
            Err(err) => {
                error!(
                    "Error while parsing {} UUID: {}",
                    request.get_ref().uuid,
                    err
                );
                return Ok(Response::new(RetrieveResponse {
                    success: false,
                    premium: false,
                    error: Error::Unspecified as i32,
                }));
            }
        };

        let regex = Regex::new(r"^\w{3,16}$").unwrap();
        if !regex.is_match(&request.get_ref().username) {
            return Ok(Response::new(RetrieveResponse {
                success: false,
                premium: false,
                error: Error::InvalidUsername as i32,
            }));
        }

        let url = format!(
            "https://api.ashcon.app/mojang/v2/user/{}",
            request.get_ref().username
        );
        let premium = match reqwest::get(url).await {
            Ok(res) => res.status() == StatusCode::OK,
            Err(err) => {
                error!("Failed to make request for {} UUID: {}", uuid, err);
                false
            }
        };

        match self.database.retrieve(uuid).await {
            Ok(player) => player,
            Err(err) => match err {
                sqlx::Error::RowNotFound => {
                    return Ok(Response::new(RetrieveResponse {
                        success: false,
                        premium,
                        error: Error::NotFound as i32,
                    }));
                }
                _ => {
                    error!("Error while retrieving data for {} UUID: {}", uuid, err);
                    return Ok(Response::new(RetrieveResponse {
                        success: false,
                        premium,
                        error: Error::Unspecified as i32,
                    }));
                }
            },
        };

        Ok(Response::new(RetrieveResponse {
            success: true,
            premium,
            error: Error::Unspecified as i32,
        }))
    }

    async fn control(
        &self,
        request: Request<ControlRequest>,
    ) -> Result<Response<ControlResponse>, Status> {
        let data = request.into_inner();

        match data.r#type {
            0 => {
                info!("unspecified");
            }
            i32::MIN..=-1_i32 | 1_i32..=i32::MAX => {
                info!("idk");
            }
        }
        Ok(Response::new(ControlResponse {
            success: false,
            error: Error::Unspecified as i32,
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logger();

    let config = match Config::builder()
        .add_source(config::File::with_name("config.yml"))
        .build()
    {
        Ok(cfg) => cfg,
        Err(err) => {
            error!("Failed to build config: {}", err);
            panic!()
        }
    };
    let config = Arc::new(config);

    info!("Connecting to the database...");
    let database = match config.get_string("database") {
        Ok(db) => db,
        Err(err) => {
            error!("Failed to retrieve database URL from config: {}", err);
            exit(1);
        }
    };

    let database = match Database::new(database).await {
        Ok(db) => db,
        Err(err) => {
            error!("Failed to connect to database: {}", err);
            exit(1);
        }
    };
    info!("Successfully connected to the database");

    let cache_ttl = match config.get_int("cache.ttl") {
        Ok(ttl) => ttl as u64,
        Err(_) => 360 as u64,
    };
    let cache_size = match config.get_int("cache.size") {
        Ok(size) => size as u64,
        Err(_) => 360 as u64,
    };

    let cache = Cache::builder()
        .time_to_live(Duration::from_secs(cache_ttl))
        .weigher(|_key: &[u8; 4], value: &bool| -> u32 { u32::from(value.to_owned()) })
        .max_capacity(cache_size * 1024 * 1024)
        .build_with_hasher(RandomState::new());

    let addr = match config.get_string("host") {
        Ok(host) => match SocketAddr::from_str(&host) {
            Ok(addr) => addr,
            Err(err) => {
                error!("Failed to parse host address: {}", err);
                exit(1);
            }
        },
        Err(err) => {
            error!("Failed to get host config: {}", err);
            exit(1);
        }
    };

    let server = MithServer {
        database,
        cache,
        config: config.clone(),
    };

    let token = match config.get_string("token") {
        Ok(token) => token,
        Err(err) => {
            error!("Failed to get token config: {}", err);
            exit(1);
        }
    };

    let service = AuthServiceServer::with_interceptor(
        server,
        move |req: Request<()>| -> Result<Request<()>, Status> { check_auth(&token, req) },
    );

    info!("Listening on {}", addr);
    if let Err(err) = Server::builder()
        .add_service(service)
        .serve_with_shutdown(addr, async {
            match signal::ctrl_c().await {
                Ok(()) => info!("Successfuly shut down the application"),
                Err(err) => error!("Unable to listen for shutdown signal: {}", err),
            }
        })
        .await
    {
        error!("Failed to start application server: {}", err);
        exit(1);
    };

    Ok(())
}
