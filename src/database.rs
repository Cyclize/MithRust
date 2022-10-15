use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use log::error;
use sha2::{Digest, Sha256};
use sqlx::{
    mysql::{MySqlConnectOptions, MySqlPoolOptions},
    types::Uuid,
    ConnectOptions, FromRow, MySql, Pool,
};
use std::str::FromStr;

use crate::error::{NewPlayerError, UpdatePasswordError};

#[derive(Debug)]
pub struct Database {
    pool: Pool<MySql>,
}

#[derive(Debug, FromRow)]
pub struct Player {
    pub uuid: Uuid,
    pub username: Vec<u8>,
    pub password: String,
    pub old_password: Option<String>,
    pub security_code: String,
    pub locked: bool,
}

impl Database {
    pub async fn new(url: String) -> Result<Database, sqlx::Error> {
        let options = match MySqlConnectOptions::from_str(&url) {
            Ok(mut opt) => opt.disable_statement_logging().clone(),
            Err(err) => {
                error!("Failed to establish a MySQL connection: {}", err);
                return Err(err);
            }
        };

        Ok(Database {
            pool: MySqlPoolOptions::new().connect_with(options).await?,
        })
    }

    pub async fn insert(&self, player: Player) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "INSERT INTO players (uuid, username, password, security_code) VALUES (?, ?, ?, ?)",
            player.uuid,
            player.username,
            player.password,
            player.security_code,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn update_password(&self, player: Player) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "UPDATE players SET password = ? WHERE uuid = ?",
            player.password,
            player.uuid,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query!(
            "UPDATE players SET old_password = ? WHERE uuid = ?",
            player.old_password,
            player.uuid,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn update_locked(&self, player: Player) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "UPDATE players SET locked = ? WHERE uuid = ?",
            player.locked,
            player.uuid,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn retrieve(&self, uuid: Uuid) -> Result<Player, sqlx::Error> {
        let player = sqlx::query_as!(
            Player,
            r#"SELECT uuid AS "uuid: Uuid", username, password, old_password, security_code, locked AS "locked: bool" FROM players WHERE uuid = ?"#,
            uuid,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(player)
    }
}

impl Player {
    pub fn new(
        uuid: String,
        username: String,
        password: String,
    ) -> Result<(Player, String), NewPlayerError> {
        let uuid = match Uuid::try_parse(&uuid) {
            Ok(uuid) => uuid,
            Err(error) => {
                error!("Failed to parse UUID {}: {}", &uuid, error);
                return Err(NewPlayerError);
            }
        };

        let password = password.as_bytes();
        let security_code_pt = Uuid::new_v4();
        let security_code = security_code_pt.as_bytes();

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let password = match argon2.hash_password(password, &salt) {
            Ok(hash) => hash.to_string(),
            Err(error) => {
                error!("Failed to hash password for {}: {}", &uuid, error);
                return Err(NewPlayerError);
            }
        };

        let security_code = match argon2.hash_password(&security_code.clone(), &salt) {
            Ok(hash) => hash.to_string(),
            Err(error) => {
                error!("Failed to hash password for {}: {}", &uuid, error);
                return Err(NewPlayerError);
            }
        };

        let mut hasher = Sha256::new();
        hasher.update(username.to_lowercase().as_bytes());
        let username = hasher.finalize()[..].to_vec();

        Ok((
            Player {
                uuid,
                username,
                old_password: None,
                password,
                security_code,
                locked: false,
            },
            security_code_pt.to_string(),
        ))
    }

    pub fn update_password(&mut self, password: String) -> Result<(), UpdatePasswordError> {
        let password = password.as_bytes();

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        self.old_password = Some(self.password.clone());
        self.password = match argon2.hash_password(password, &salt) {
            Ok(hash) => hash.to_string(),
            Err(error) => {
                error!("Failed to hash password for {}: {}", &self.uuid, error);
                return Err(UpdatePasswordError);
            }
        };

        Ok(())
    }

    pub fn update_locked(&mut self, locked: bool) -> () {
        self.locked = locked;
    }
}
