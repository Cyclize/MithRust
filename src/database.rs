use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use log::error;
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
    pub password: String,
    pub security_code: String,
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
            "INSERT INTO players (uuid, password, security_code) VALUES (?, ?, ?)",
            player.uuid,
            player.password,
            player.security_code,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn update(&self, player: Player) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "UPDATE players SET password = ? WHERE uuid = ?",
            player.password,
            player.uuid,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn retrieve(&self, uuid: Uuid) -> Result<Player, sqlx::Error> {
        let player = sqlx::query_as!(
            Player,
            r#"SELECT uuid AS "uuid: Uuid", password, security_code FROM players WHERE uuid = ?"#,
            uuid,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(player)
    }
}

impl Player {
    pub fn new(uuid: String, password: String) -> Result<(Player, String), NewPlayerError> {
        let uuid = match Uuid::try_parse(&uuid) {
            Ok(uuid) => uuid,
            Err(error) => {
                error!("Failed to parse UUID {}: {}", &uuid, error);
                return Err(NewPlayerError);
            }
        };

        let password = password.as_bytes();
        let security_code = Uuid::new_v4();
        let security_code = security_code.as_bytes();

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

        Ok((
            Player {
                uuid,
                password,
                security_code: security_code.clone(),
            },
            security_code,
        ))
    }

    pub fn update_password(&mut self, password: String) -> Result<(), UpdatePasswordError> {
        let password = password.as_bytes();

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        self.password = match argon2.hash_password(password, &salt) {
            Ok(hash) => hash.to_string(),
            Err(error) => {
                error!("Failed to hash password for {}: {}", &self.uuid, error);
                return Err(UpdatePasswordError);
            }
        };

        Ok(())
    }
}
