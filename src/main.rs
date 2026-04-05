use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;
use std::env;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use x25519_dalek::{EphemeralSecret, PublicKey};

// TUI 相关引用
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame, Terminal,
};
use unicode_width::UnicodeWidthStr;

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
        }
        "client" => run_client(&args[2]).await?,
        _ => println!("未知命令"),
    }

    Ok(())
}

/// ==========================================
/// 服务端代码：一个瞎子邮局（盲目转发数据）
/// ==========================================

async fn run_server_with_default_addr() -> Result<(), Box<dyn std::error::Error>> {
    run_server("0.0.0.0:19198").await
}

async fn run_server(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(addr).await?;
    println!("🚀 服务器已启动，等待两人连接 ({})...", addr);

    let (tx, mut rx) = mpsc::channel::<(TcpStream, [u8; 32])>(100);

    tokio::spawn(async move {
        loop {
            let (mut client_a, pub_a) = match rx.recv().await {
                Some(c) => c,
                None => break,
            };
            println!("✅ 真实用户 A 已就绪，等待用户 B...");

            let (mut client_b, pub_b) = match rx.recv().await {
                Some(c) => c,
                None => break,
            };
            println!("✅ 真实用户 B 已就绪！正在交换公钥并建立桥接...");

            if client_a.write_all(&pub_b).await.is_err()
                || client_b.write_all(&pub_a).await.is_err()
            {
                println!("⚠️ 交换密钥失败，可能有人断开了连接");
                continue;
            }

            tokio::spawn(async move {
                let _ = tokio::io::copy_bidirectional(&mut client_a, &mut client_b).await;
                println!("❌ 这对用户的聊天已结束，连接断开");
            });
        }
    });

    loop {
        let (mut stream, addr) = listener.accept().await?;
        println!("📡 收到新连接: {} (等待验证是否为真实用户...)", addr);
        let tx = tx.clone();

        tokio::spawn(async move {
            let mut pub_key = [0u8; 32];
            match timeout(Duration::from_secs(30), stream.read_exact(&mut pub_key)).await {
                Ok(Ok(_)) => {
                    println!("🔑 收到来自 {} 的公钥，确认为活跃用户！", addr);
                    let _ = tx.send((stream, pub_key)).await;
                }
                Ok(Err(_)) => println!("👻 连接 {} 断开或数据不足", addr),
                Err(_) => println!(
                    "💤 连接 {} 等待超时，已忽略 (这通常是穿透软件的预留空连接)",
                    addr
                ),
            }
        });
    }
}

/// ==========================================
/// 客户端代码：端到端加密的核心 (带 TUI 界面)
/// ==========================================

/// 聊天消息结构
struct Message {
    sender: String,
    content: String,
}

/// TUI 应用程序状态
struct App {
    input: String,
    messages: Vec<Message>,
}

impl App {
    fn new() -> App {
        App {
            input: String::new(),
            messages: Vec::new(),
        }
    }
}

async fn run_client(server_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(server_addr).await?;
    stream.set_nodelay(true)?;

    println!("✅ 已连接到服务器，等待对方上线以交换密钥...");

    let my_secret = EphemeralSecret::random_from_rng(OsRng);
    let my_public = PublicKey::from(&my_secret);

    stream.write_all(my_public.as_bytes()).await?;

    let mut peer_public_bytes = [0u8; 32];
    stream.read_exact(&mut peer_public_bytes).await?;
    let peer_public = PublicKey::from(peer_public_bytes);

    let shared_secret = my_secret.diffie_hellman(&peer_public);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes()));

    // --- 设置 TUI 终端 ---
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let (mut reader, mut writer) = stream.into_split();
    let cipher_clone = cipher.clone();

    // 通道：从网络接收到的消息
    let (net_tx, mut net_rx) = mpsc::channel::<String>(100);
    // 通道：发送给网络的消息
    let (ui_tx, mut ui_rx) = mpsc::channel::<String>(100);

    // --- 任务 1：网络接收任务 ---
    let read_task = tokio::spawn(async move {
        loop {
            let mut len_bytes = [0u8; 4];
            if reader.read_exact(&mut len_bytes).await.is_err() {
                break;
            }
            let msg_len = u32::from_be_bytes(len_bytes) as usize;

            let mut encrypted_data = vec![0u8; msg_len];
            if reader.read_exact(&mut encrypted_data).await.is_err() {
                break;
            }

            let nonce = Nonce::from_slice(&encrypted_data[0..12]);
            let ciphertext = &encrypted_data[12..];

            if let Ok(plaintext) = cipher_clone.decrypt(nonce, ciphertext) {
                let msg = String::from_utf8_lossy(&plaintext).to_string();
                let _ = net_tx.send(msg).await;
            }
        }
    });

    // --- 任务 2：网络发送任务 ---
    let write_task = tokio::spawn(async move {
        while let Some(text) = ui_rx.recv().await {
            let mut nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            if let Ok(ciphertext) = cipher.encrypt(nonce, text.as_bytes()) {
                let mut payload = Vec::new();
                payload.extend_from_slice(&nonce_bytes);
                payload.extend_from_slice(&ciphertext);

                let len_bytes = (payload.len() as u32).to_be_bytes();
                if writer.write_all(&len_bytes).await.is_err() || writer.write_all(&payload).await.is_err() {
                    break;
                }
            }
        }
    });

    // --- 任务 3：UI 主循环 ---
    let mut app = App::new();
    let res = run_tui_loop(&mut terminal, &mut app, &mut net_rx, ui_tx).await;

    // --- 清理 TUI 并还原终端 ---
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("❌ 运行错误: {:?}", err);
    }

    // 终止其他任务
    read_task.abort();
    write_task.abort();

    Ok(())
}

/// TUI 事件循环
async fn run_tui_loop<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    net_rx: &mut mpsc::Receiver<String>,
    ui_tx: mpsc::Sender<String>,
) -> Result<(), Box<dyn std::error::Error>>
where
    B::Error: std::error::Error + 'static,
{
    loop {
        // 渲染界面
        terminal.draw(|f| ui_draw(f, app))?;

        // 检查是否有来自网络的输入 (非阻塞检查)
        while let Ok(msg) = net_rx.try_recv() {
            app.messages.push(Message {
                sender: "对方".to_string(),
                content: msg,
            });
        }

        // 检查键盘事件
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                // 关键点：在 Windows 上，我们需要过滤掉 Release 释放事件，只保留 Press 按下事件
                // 否则会出现按一下出两个字母的 BUG
                if key.kind == event::KeyEventKind::Press {
                    match key.code {
                        KeyCode::Enter => {
                            let text: String = app.input.drain(..).collect();
                            if !text.is_empty() {
                                app.messages.push(Message {
                                    sender: "我".to_string(),
                                    content: text.clone(),
                                });
                                let _ = ui_tx.try_send(text);
                            }
                        }
                        KeyCode::Char(c) => {
                            app.input.push(c);
                        }
                        KeyCode::Backspace => {
                            app.input.pop();
                        }
                        KeyCode::Esc => {
                            return Ok(());
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

/// 界面绘制逻辑
fn ui_draw(f: &mut Frame, app: &App) {
    // 划分为上下两部分：上部是聊天记录，下部是输入框
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(f.area());

    // 1. 聊天记录列表
    // 计算可显示的行数（减去边框）
    let list_height = chunks[0].height.saturating_sub(2) as usize;
    let messages_to_show = if app.messages.len() > list_height {
        &app.messages[app.messages.len() - list_height..]
    } else {
        &app.messages[..]
    };

    let messages: Vec<ListItem> = messages_to_show
        .iter()
        .map(|m| {
            let style = if m.sender == "我" {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default().fg(Color::Green)
            };
            let content = format!("{}: {}", m.sender, m.content);
            ListItem::new(content).style(style)
        })
        .collect();

    let messages_list = List::new(messages)
        .block(Block::default().borders(Borders::ALL).title(" 💬 端到端加密聊天 "));
    f.render_widget(messages_list, chunks[0]);

    // 2. 输入框
    let input = Paragraph::new(app.input.as_str())
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().borders(Borders::ALL).title(" 📝 输入消息 (Esc 退出) "));
    f.render_widget(input, chunks[1]);

    // 设置光标位置到输入框末尾
    // 使用 UnicodeWidthStr 计算实际显示宽度，而不是字节长度
    f.set_cursor_position((chunks[1].x + app.input.width() as u16 + 1, chunks[1].y + 1));
}
