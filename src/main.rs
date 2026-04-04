use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;
use std::env;
use std::io::{self, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use x25519_dalek::{EphemeralSecret, PublicKey};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("错误: 缺少参数");
        eprintln!("请查看 README.md 文件了解如何使用此程序");
        return Ok(());
    }

    match args[1].as_str() {
        "server" => {
            if args.len() < 3 {
                run_server_with_default_addr().await?
            } else {
                run_server(&args[2]).await?
            }
        },
        "client" => run_client(&args[2]).await?,
        _ => println!("未知命令"),
    }

    Ok(())
}

/// ==========================================
/// 服务端代码：一个瞎子邮局（盲目转发数据）
/// ==========================================

/// 使用默认地址运行服务器
async fn run_server_with_default_addr() -> Result<(), Box<dyn std::error::Error>> {
    run_server("0.0.0.0:19198").await
}

/// 使用指定地址运行服务器
/// ==========================================
/// 服务端代码：智能抗干扰瞎子邮局
/// ==========================================
async fn run_server(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(addr).await?;
    println!("🚀 服务器已启动，等待两人连接 ({})...", addr);

    // 创建一个通道，用来收集“真正发送了公钥的活跃用户”
    // 穿透软件的空连接池不会发数据，所以进不了这个通道
    let (tx, mut rx) = mpsc::channel::<(TcpStream, [u8; 32])>(100);

    // --- 后台任务 1：专门负责将活跃用户两两配对 ---
    tokio::spawn(async move {
        loop {
            // 等待第一个活跃用户
            let (mut client_a, pub_a) = match rx.recv().await {
                Some(c) => c,
                None => break,
            };
            println!("✅ 真实用户 A 已就绪，等待用户 B...");

            // 等待第二个活跃用户
            let (mut client_b, pub_b) = match rx.recv().await {
                Some(c) => c,
                None => break,
            };
            println!("✅ 真实用户 B 已就绪！正在交换公钥并建立桥接...");

            // 核心：由服务器充当中间人，把 A 的公钥发给 B，B 的公钥发给 A
            if client_a.write_all(&pub_b).await.is_err() || client_b.write_all(&pub_a).await.is_err() {
                println!("⚠️ 交换密钥失败，可能有人断开了连接");
                continue;
            }

            // 启动桥接，开始盲目转发聊天数据
            tokio::spawn(async move {
                let _ = tokio::io::copy_bidirectional(&mut client_a, &mut client_b).await;
                println!("❌ 这对用户的聊天已结束，连接断开");
            });
        }
    });

    // --- 主循环：无限接收新的 TCP 连接 ---
    loop {
        let (mut stream, addr) = listener.accept().await?;
        println!("📡 收到新连接: {} (等待验证是否为真实用户...)", addr);
        let tx = tx.clone();

        // 为每个连接开一个独立任务去读取前 32 字节，不阻塞其他连接接入
        tokio::spawn(async move {
            let mut pub_key = [0u8; 32];
            // 设置 30 秒超时，防止内网穿透的空闲连接池永远占用资源
            match timeout(Duration::from_secs(30), stream.read_exact(&mut pub_key)).await {
                Ok(Ok(_)) => {
                    println!("🔑 收到来自 {} 的公钥，确认为活跃用户！", addr);
                    // 把确认是活人的连接和它发来的公钥丢给配对任务
                    let _ = tx.send((stream, pub_key)).await;
                }
                Ok(Err(_)) => println!("👻 连接 {} 断开或数据不足", addr),
                Err(_) => println!("💤 连接 {} 等待超时，已忽略 (这通常是穿透软件的预留空连接)", addr),
            }
        });
    }
}
/// ==========================================
/// 客户端代码：端到端加密的核心
/// ==========================================
async fn run_client(server_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(server_addr).await?;

    // 👇 新增这一行：禁用 Nagle 算法，要求 TCP 立即发送数据包，不要等待！
    stream.set_nodelay(true)?; 

    println!("✅ 已连接到服务器，等待对方上线以交换密钥...");

    // 1. 生成一次性椭圆曲线私钥 (Ephemeral Secret) 和公钥
    let my_secret = EphemeralSecret::random_from_rng(OsRng);
    let my_public = PublicKey::from(&my_secret);

    // 2. 将我的公钥（32字节）发给对方
    stream.write_all(my_public.as_bytes()).await?;

    // 3. 接收对方的公钥（32字节）
    let mut peer_public_bytes = [0u8; 32];
    stream.read_exact(&mut peer_public_bytes).await?;
    let peer_public = PublicKey::from(peer_public_bytes);

    // 4. 见证奇迹的时刻：用我的私钥 + 对方的公钥 = 算出共享密钥 (Shared Secret)
    // 根据数学原理，对方也能算出完全一样的值！这就是端到端加密的基础。
    let shared_secret = my_secret.diffie_hellman(&peer_public);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes()));

    println!("🔒 端到端加密通道已建立！密钥交换成功。现在开始聊天吧。\n");

    // 将网络流分成 "读" 和 "写" 两部分
    let (mut reader, mut writer) = stream.into_split();
    let cipher_clone = cipher.clone();

    // --- 任务 1：从网络接收消息，解密并显示 ---
    let read_task = tokio::spawn(async move {
        loop {
            // 先读取 4 字节的长度信息
            let mut len_bytes = [0u8; 4];
            if reader.read_exact(&mut len_bytes).await.is_err() {
                break;
            }
            let msg_len = u32::from_be_bytes(len_bytes) as usize;

            // 根据长度读取加密的密文 (包含 Nonce + 密文)
            let mut encrypted_data = vec![0u8; msg_len];
            if reader.read_exact(&mut encrypted_data).await.is_err() {
                break;
            }

            // 提取前 12 字节作为 Nonce，后面的是实际密文
            let nonce = Nonce::from_slice(&encrypted_data[0..12]);
            let ciphertext = &encrypted_data[12..];

            // 核心：解密！如果数据被服务器篡改，这一步会报错（AES-GCM 带有完整性校验）
            match cipher_clone.decrypt(nonce, ciphertext) {
                Ok(plaintext) => {
                    let msg = String::from_utf8_lossy(&plaintext);
                    // 清除当前输入行，打印对方消息，然后恢复光标 (简陋的 TUI 体验)
                    print!("\r\x1b[2K"); // ANSI 转义码：回到行首并清空当前行
                    println!("🟢 对方: {}", msg);
                    print!("🔵 我: "); // 重新打印提示符
                    io::stdout().flush().unwrap();
                }
                Err(_) => println!("\n⚠️ 警告：收到无法解密的数据包！可能被篡改。"),
            }
        }
    });

    // --- 任务 2：读取键盘输入，加密并发送到网络 ---
    let write_task = tokio::spawn(async move {
        let stdin = std::io::stdin();
        let mut buffer = String::new();

        loop {
            print!("🔵 我: ");
            io::stdout().flush().unwrap();
            buffer.clear();

            // 这是一个阻塞操作，在实际的高级 TUI (如 ratatui) 中会用非阻塞事件循环
            // 但为了代码简洁，这里用标准输入
            if stdin.read_line(&mut buffer).is_err() {
                break;
            }
            let text = buffer.trim();
            if text.is_empty() {
                continue;
            }

            // 1. 生成随机的 12 字节 Nonce (防止重放攻击，每次加密必须不同)
            let mut nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            // 2. 核心：加密聊天文本！
            let ciphertext = cipher.encrypt(nonce, text.as_bytes()).expect("加密失败");

            // 3. 将 Nonce 和 密文 拼装在一起
            let mut payload = Vec::new();
            payload.extend_from_slice(&nonce_bytes);
            payload.extend_from_slice(&ciphertext);

            // 4. 先发送长度，再发送数据本体 (解决 TCP 粘包问题)
            let len_bytes = (payload.len() as u32).to_be_bytes();
            writer.write_all(&len_bytes).await.unwrap();
            writer.write_all(&payload).await.unwrap();
        }
    });

    // 等待任何一个任务结束（比如有人退出了）
    tokio::select! {
        _ = read_task => {},
        _ = write_task => {},
    }

    Ok(())
}