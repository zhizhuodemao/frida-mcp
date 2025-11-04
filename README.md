# Frida MCP Server | Frida MCP 服务器

[English](#english) | [中文](#中文)

## English

A Model Context Protocol (MCP) server that enables AI models to perform Android dynamic analysis using Frida.

### Project Structure

```
frida-mcp/
├── frida_mcp.py          # Core MCP server implementation
├── pyproject.toml        # Project dependencies and configuration  
├── requirements.txt      # Alternative dependency file
├── config.json           # Optional Frida server configuration
├── README.md            # Documentation
└── .gitignore           # Git ignore rules
```

### Core Files

- **`frida_mcp.py`**: Main MCP server with Frida integration
- **`pyproject.toml`**: Modern Python project configuration (recommended)
- **`requirements.txt`**: Traditional dependency file
- **`config.json`**: Optional configuration for frida-server settings

### Installation

```bash
# Clone repository
git clone http://git.dev.sh.ctripcorp.com/octopus/frida-mcp.git
cd frida-mcp

# Install dependencies (choose one method)
# Method 1: Using pip + requirements.txt
pip install -r requirements.txt

# Method 2: Using pip + pyproject.toml (recommended)
pip install -e .

# Setup frida-server on Android device
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c /data/local/tmp/frida-server &"
```

### MCP Configuration

Add to your MCP client configuration (e.g., Claude Desktop config file):

**Windows** (`%APPDATA%\Claude\claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "frida": {
      "command": "python",
      "args": ["C:\\Users\\YourName\\frida-mcp\\frida_mcp.py"],
      "transport": "stdio"
    }
  }
}
```

**macOS/Linux** (`~/.config/claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "frida": {
      "command": "python",
      "args": ["/home/username/frida-mcp/frida_mcp.py"],
      "transport": "stdio"
    }
  }
}
```

### Configuration (Optional)

The `config.json` file contains optional Frida server configuration:

```json
{
  "server_path": "/data/local/myfr",
  "server_name": "aaabbb", 
  "server_port": 27042,
  "device_id": null,
  "adb_path": "adb"
}
```

- `server_path`: Custom path for frida-server on Android device
- `server_name`: Custom frida-server binary name
- `server_port`: Port for Frida server communication
- `device_id`: Specific device ID (null for auto-detection)
- `adb_path`: Path to ADB executable

### Available Tools

#### `spawn(package_name, initial_script?, wait_seconds?, max_output_messages?)`
Start an Android application with optional script injection.

#### `attach(target, initial_script?, wait_seconds?, max_output_messages?)`
Attach to a running process with optional script injection.

#### `get_frontmost_application()`
Get the currently active application.

#### `list_applications()`
List all installed applications.

### Example Usage

```javascript
// Hook HashMap operations
Java.perform(function() {
    var HashMap = Java.use("java.util.HashMap");
    HashMap.put.implementation = function(key, value) {
        console.log("HashMap.put:", key, value);
        return this.put(key, value);
    };
});
```

---

## 中文

一个 Model Context Protocol (MCP) 服务器，使 AI 模型能够使用 Frida 进行 Android 动态分析。

### 项目结构

```
frida-mcp/
├── frida_mcp.py          # MCP 服务器核心实现
├── pyproject.toml        # 项目依赖和配置文件
├── requirements.txt      # 传统依赖文件
├── config.json           # 可选的 Frida 服务器配置
├── README.md            # 文档说明
└── .gitignore           # Git 忽略规则
```

### 核心文件

- **`frida_mcp.py`**: 集成 Frida 的主要 MCP 服务器
- **`pyproject.toml`**: 现代 Python 项目配置（推荐使用）
- **`requirements.txt`**: 传统依赖文件
- **`config.json`**: Frida 服务器设置的可选配置文件

### 安装

```bash
# 克隆仓库
git clone http://git.dev.sh.ctripcorp.com/octopus/frida-mcp.git
cd frida-mcp

# 安装依赖（选择一种方法）
# 方法1：使用 pip + requirements.txt
pip install -r requirements.txt

# 方法2：使用 pip + pyproject.toml（推荐）
pip install -e .

# 在 Android 设备上设置 frida-server
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c /data/local/tmp/frida-server &"
```

### MCP 配置

添加到您的 MCP 客户端配置（如 Claude Desktop 配置文件）：

**Windows** (`%APPDATA%\Claude\claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "frida": {
      "command": "python",
      "args": ["C:\\Users\\你的用户名\\frida-mcp\\frida_mcp.py"],
      "transport": "stdio"
    }
  }
}
```
注意：将 `你的用户名` 替换为实际的 Windows 用户名，路径使用双反斜杠 `\\`

**macOS/Linux** (`~/.config/claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "frida": {
      "command": "python",
      "args": ["/home/用户名/frida-mcp/frida_mcp.py"],
      "transport": "stdio"
    }
  }
}
```
注意：将 `用户名` 替换为实际的系统用户名
```

### 配置说明（可选）

`config.json` 文件包含可选的 Frida 服务器配置：

```json
{
  "server_path": "/data/local/myfr",
  "server_name": "aaabbb", 
  "server_port": 27042,
  "device_id": null,
  "adb_path": "adb"
}
```

- `server_path`: Android 设备上 frida-server 的自定义路径
- `server_name`: frida-server 二进制文件的自定义名称
- `server_port`: Frida 服务器通信端口
- `device_id`: 指定设备 ID（null 为自动检测）
- `adb_path`: ADB 可执行文件路径

### 可用工具

#### `spawn(package_name, initial_script?, wait_seconds?, max_output_messages?)`
启动 Android 应用程序，可选注入脚本。

- `package_name`: 应用包名
- `initial_script`: 可选的 JavaScript 脚本
- `wait_seconds`: 等待输出的时间（默认 1.5 秒）
- `max_output_messages`: 最大输出消息数（默认 100）

#### `attach(target, initial_script?, wait_seconds?, max_output_messages?)`
附加到运行中的进程，可选注入脚本。

- `target`: 进程名或 PID
- `initial_script`: 可选的 JavaScript 脚本
- `wait_seconds`: 等待输出的时间（默认 1.0 秒）
- `max_output_messages`: 最大输出消息数（默认 100）

#### `get_frontmost_application()`
获取当前活跃的应用程序。

#### `list_applications()`
列出所有已安装的应用程序。

### 使用示例

```javascript
// Hook HashMap 操作
Java.perform(function() {
    var HashMap = Java.use("java.util.HashMap");
    HashMap.put.implementation = function(key, value) {
        console.log("HashMap.put:", key, value);
        return this.put(key, value);
    };
});
```

### 特性

- 🚀 自动 Gson 对象序列化
- 🔍 console.log 自动重定向
- 📱 自动设备连接管理
- 🤖 为 AI 交互优化

### 常见问题

**Q: 应用崩溃怎么办？**
A: 减少 hook 频率，避免复杂序列化操作。

**Q: 没有输出？**
A: 确认方法被调用，spawn 时脚本在应用启动前注入。

**Q: 连接失败？**
A: 检查 frida-server 是否运行：`adb shell ps | grep frida`

### Requirements

- Python 3.8+
- Android 设备 (root)
- 查看 `requirements.txt`

## License

MIT