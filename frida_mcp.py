"""
Frida MCP Server - Minimal Android Hook Service using FastMCP
"""

import time
import asyncio
import json
import os
from typing import Optional, Dict, Any, Deque
from collections import defaultdict, deque
from device_manager import DeviceManager
import frida
from mcp.server.fastmcp import FastMCP


# Global state management - simplified
device: Optional[frida.core.Device] = None
session: Optional[frida.core.Session] = None

# Global message buffer (store raw log lines)
messages_buffer: Deque[str] = deque(maxlen=5000)

# Keep strong references to loaded scripts to prevent GC unloading
active_scripts = []

# Append client-side Frida logs to the global buffer
def _frida_log(text: str) -> None:
    try:
        messages_buffer.append(f"[frida] {text}")
    except Exception:
        pass

# Bind session events to capture detach reasons (e.g., target crash/kill)
def _bind_session_events(sess: frida.core.Session) -> None:
    try:
        def on_detached(reason):
            _frida_log(f"session detached: {reason}")
        sess.on('detached', on_detached)
    except Exception as e:
        _frida_log(f"bind detached failed: {e}")

# Initialize FastMCP
app = FastMCP("frida-mcp")


# Minimal configuration loading from config.json (optional)
def _load_config() -> Dict[str, Any]:
    default_config: Dict[str, Any] = {
        "server_path": None,
        "server_name": None,
        "server_port": 27042,
        "device_id": None,
        "adb_path": "adb",
    }
    # Try relative to this file first, then CWD
    candidates = [
        os.path.join(os.path.dirname(__file__), "config.json"),
        os.path.join(os.getcwd(), "config.json"),
    ]
    for cfg in candidates:
        try:
            if os.path.isfile(cfg):
                with open(cfg, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    default_config.update(loaded)
                break
        except Exception:
            # Silently fall back to defaults for minimal intrusion
            break
    return default_config


CONFIG = _load_config()



# Independent script wrapper function to prevent stdout pollution
def wrap_script_for_mcp(user_script: str) -> str:
    """
    独立函数，包装用户脚本，重定向console.log避免stdout污染，支持Gson转换对象
    
    Args:
        user_script: 用户提供的JavaScript脚本
        
    Returns:
        包装后的脚本，console.log被重定向到send()，对象自动Gson转换
    """
    return f"""
    // 智能对象转字符串函数（优先使用Gson）
    function safeStringify(obj) {{
        if (obj === null) return 'null';
        if (obj === undefined) return 'undefined';
        
        // 基本类型直接返回
        if (typeof obj === 'string') return obj;
        if (typeof obj === 'number' || typeof obj === 'boolean') return String(obj);
        
        // 对象类型尝试转换
        try {{
            // 优先尝试Gson（如果应用有Gson库）
            var Gson = Java.use('com.google.gson.Gson');
            var gson = Gson.$new();
            return gson.toJson(obj);
        }} catch (gsonError) {{
            try {{
                // Fallback到toString()
                return obj.toString();
            }} catch (toStringError) {{
                try {{
                    // 最后尝试获取类名
                    return '[' + (obj.$className || 'Unknown') + ' Object]';
                }} catch (classError) {{
                    return '[Unparseable Object]';
                }}
            }}
        }}
    }}
    
    // 重定向console.log到send()避免stdout污染
    console.log = function() {{
        var message = Array.prototype.slice.call(arguments).map(function(arg) {{
            return safeStringify(arg);
        }}).join(' ');
        send({{'type': 'log', 'message': message}});
    }};
    
    // 用户脚本
    {user_script}
    """


# Helper function to create message collector for script output
def create_message_collector(external_buffer: Optional[Deque[str]] = None, output_file: Optional[str] = None):
    """
    Creates a message handler that collects Frida script output for later retrieval.

    Args:
        external_buffer: Optional buffer to append messages to
        output_file: Optional LOCAL file path to write messages to (NOT Android device path)

    Returns:
        Tuple of (message_handler function, messages list)
    """
    messages = []
    
    # If output file exists, clear it; if not, it will be created on first write
    if output_file and os.path.exists(output_file):
        try:
            open(output_file, 'w', encoding='utf-8').close()
        except Exception:
            pass

    def on_message(message, data):
        # Handle different message types
        if message.get('type') == 'send':
            payload = message.get('payload', {})
            if isinstance(payload, dict) and payload.get('type') == 'log':
                # This is a console.log message redirected by our wrapper
                text = payload.get('message', str(payload))
            else:
                # Other send() messages
                text = str(payload)
        elif message.get('type') == 'error':
            # Script errors
            text = f"[Error] {message.get('stack', message.get('description', str(message)))}"
        else:
            # Other message types
            if 'payload' in message:
                text = str(message['payload'])
            else:
                text = str(message)

        messages.append(text)
        if external_buffer is not None:
            external_buffer.append(text)

        # Write to LOCAL output file if specified (saved on computer running MCP server)
        if output_file:
            try:
                with open(output_file, 'a', encoding='utf-8') as f:
                    f.write(f"{text}\n")
            except Exception:
                pass  # Silently handle file write errors to avoid disrupting the main flow

    return on_message, messages


# Helper to load initial script and wire global message buffer
async def _load_script_with_global_buffer(session: frida.core.Session, initial_script: Optional[str], init_delay_seconds: float = 0.0, output_file: Optional[str] = None) -> bool:
    """
    Load script and wire to global message buffer with optional local file output.
    
    Args:
        session: Frida session
        initial_script: JavaScript code to load
        init_delay_seconds: Delay after script loading
        output_file: Optional LOCAL file path for saving output (NOT Android device path)
    
    Returns:
        True if script loaded successfully, False otherwise
    """
    if not initial_script:
        return False
    wrapped_script = wrap_script_for_mcp(initial_script)
    script = session.create_script(wrapped_script)
    # Clear global buffer
    try:
        while len(messages_buffer) > 0:
            messages_buffer.pop()
    except Exception:
        pass
    handler, _ = create_message_collector(messages_buffer, output_file)
    script.on('message', handler)
    script.load()
    # Keep reference so script isn't garbage-collected (which would unload it)
    active_scripts.append(script)
    if init_delay_seconds and init_delay_seconds > 0:
        try:
            await asyncio.sleep(init_delay_seconds)
        except Exception:
            pass
    return True

def _resolve_script_content(initial_script: Optional[str], script_file_path: Optional[str]) -> tuple[Optional[str], Optional[Dict[str, Any]]]:
    """
    解析脚本内容，优先使用文件路径，fallback到代码字符串
    
    Args:
        initial_script: JS代码字符串
        script_file_path: JS文件绝对路径
        
    Returns:
        tuple: (script_content, error_response)
        - 成功时返回 (script_content_string, None)
        - 失败时返回 (None, error_dict)
    """
    if script_file_path:
        if not os.path.isabs(script_file_path):
            return None, {
                "status": "error",
                "message": "script_file_path must be an absolute path"
            }
        if not script_file_path.endswith('.js'):
            return None, {
                "status": "error", 
                "message": "script_file_path must be a .js file"
            }
        try:
            with open(script_file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            _frida_log(f"Loaded JS script from file: {script_file_path}")
            return content, None
        except Exception as e:
            return None, {
                "status": "error",
                "message": f"Failed to read JS file {script_file_path}: {str(e)}"
            }
    elif initial_script:
        return initial_script, None
    else:
        return None, None

# Internal helper function for device connection
async def ensure_device_connected(device_id: Optional[str] = None) -> bool:
    """
    Internal helper to ensure device is connected.
    Returns True if successful, False otherwise.
    """
    global device
    
    if device:
        try:
            # Test if device is still connected
            device.id
            return True
        except:
            device = None
    
    # Resolution order (minimal change):
    # 1) Explicit device_id param
    # 2) device_id from CONFIG
    # 3) USB device
    # 4) Remote device via localhost:server_port (requires external port-forward)
    device_id_to_use = device_id or CONFIG.get("device_id")
    try:
        if device_id_to_use:
            device = frida.get_device(device_id_to_use)
            return True
    except Exception:
        pass
    try:
        device = frida.get_usb_device(timeout=5)
        return True
    except Exception:
        pass
    try:
        port = int(CONFIG.get("server_port") or 27042)
        # Ensure ADB port forwarding before attempting remote connect
        try:
            dm = DeviceManager()
            dm.setup_port_forward(str(port))
            time.sleep(0.5)
        except Exception:
            pass
        manager = frida.get_device_manager()
        device_remote = manager.add_remote_device(f"127.0.0.1:{port}")
        if device_remote:
            device = device_remote
            return True
    except Exception:
        pass
    return False


# Resolve frida-server path from CONFIG with minimal rules
def _resolve_server_path_from_config() -> str:
    base = (CONFIG.get("server_path") or "").rstrip("/")
    name = CONFIG.get("server_name")
    if base and name:
        return f"{base}/{name}"
    if base:
        return base
    if name:
        return f"/data/local/tmp/{name}"
    return "/data/local/tmp/frida-server"


@app.tool()
async def start_frida_server() -> Dict[str, Any]:
    """
    启动设备上的 frida-server。

    - 来源: 使用 config.json 的 server_path/server_name/server_port
    - 返回: {status, path, port, message}
    """
    dm = DeviceManager()
    # If already running, no-op
    if dm.check_frida_status(silent=True):
        return {
            "status": "success",
            "message": "frida-server already running",
        }
    path = _resolve_server_path_from_config()
    port_value = int(CONFIG.get("server_port") or 27042)
    ok = dm.start_frida_server(server_path=path, port=str(port_value))
    return {
        "status": "success" if ok else "error",
        "path": path,
        "port": port_value,
        "message": "frida-server started" if ok else "failed to start frida-server"
    }


@app.tool()
async def stop_frida_server() -> Dict[str, Any]:
    """
    停止设备上的 frida-server。

    - 返回: {status, message}
    """
    dm = DeviceManager()
    # If not running, no-op
    if not dm.check_frida_status(silent=True):
        return {"status": "success", "message": "frida-server already stopped"}
    ok = dm.stop_frida_server()
    return {"status": "success" if ok else "error", "message": "frida-server stopped" if ok else "failed to stop frida-server"}


@app.tool()
async def check_frida_status() -> Dict[str, Any]:
    """
    检测 frida-server 是否在运行。

    - 返回: {status, running}
    """
    dm = DeviceManager()
    running = bool(dm.check_frida_status(silent=True))
    return {"status": "success", "running": running}


@app.tool()
async def get_messages(max_messages: int = 100) -> Dict[str, Any]:
    """
    获取全局 hook/log 文本缓冲（非消费模式）。

    Args:
      - max_messages: 返回的最大条数（默认 100）

    Returns:
      - {status, messages, remaining}
    """
    if max_messages is None or max_messages < 0:
        max_messages = 0
    buffer = messages_buffer
    if not buffer or len(buffer) == 0:
        return {
            "status": "success",
            "messages": [],
            "remaining": 0
        }
    snapshot = list(buffer)
    if max_messages > 0:
        snapshot = snapshot[-max_messages:]
    else:
        snapshot = []
    return {
        "status": "success",
        "messages": snapshot,
        "remaining": len(buffer)
    }


# MCP Tool Handlers using FastMCP decorators


@app.tool()
async def get_frontmost_application() -> Dict[str, Any]:
    """
    获取当前前台应用信息。

    - 返回: {status, application?{identifier,name,pid}, message?}
    """
    if not await ensure_device_connected():
        return {
            "status": "error",
            "message": "Failed to connect to device. Ensure frida-server is running."
        }
    
    try:
        frontmost = device.get_frontmost_application()
        if frontmost:
            return {
                "status": "success",
                "application": {
                    "identifier": frontmost.identifier,
                    "name": frontmost.name,
                    "pid": frontmost.pid
                }
            }
        else:
            return {
                "status": "success",
                "application": None,
                "message": "No frontmost application found"
            }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


@app.tool()
async def list_applications() -> Dict[str, Any]:
    """
    列出设备上的已安装应用（含运行与未运行）。

    - 返回: {status, count, applications:[{identifier,name,pid?}]}
    """
    if not await ensure_device_connected():
        return {
            "status": "error",
            "message": "Failed to connect to device. Ensure frida-server is running."
        }
    
    try:
        applications = device.enumerate_applications()
        app_list = []
        for app in applications:
            app_list.append({
                "identifier": app.identifier,
                "name": app.name,
                "pid": app.pid if hasattr(app, 'pid') else None
            })
        
        # Sort by name for easier reading
        app_list.sort(key=lambda x: x["name"].lower())
        
        return {
            "status": "success",
            "count": len(app_list),
            "applications": app_list
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


@app.tool()
async def attach(
    target: str,
    initial_script: Optional[str] = None,
    script_file_path: Optional[str] = None,
    output_file: Optional[str] = None
) -> Dict[str, Any]:
    """
    附加到运行中的进程，并可选注入脚本。

    Args:
      - target: PID 字符串或包名
      - initial_script: 可选注入的 Frida JS 代码字符串
      - script_file_path: 可选注入的 JS 文件绝对路径（优先于 initial_script）
      - output_file: 可选的本地电脑文件路径，用于保存 hook 输出（非安卓设备路径）

    Returns:
      - {status, pid, target, name, script_loaded, message}
    """
    global session
    
    # Clean up old session if exists
    if session:
        try:
            session.detach()
        except:
            pass  # Session might already be disconnected
        session = None
    
    # Ensure device is connected
    if not await ensure_device_connected():
        return {
            "status": "error",
            "message": "Failed to connect to device. Ensure frida-server is running."
        }
    
    if not target or not target.strip():
        return {
            "status": "error",
            "message": "Target cannot be empty"
        }
    
    target = target.strip()
    
    try:
        # Determine PID
        if target.isdigit():
            pid = int(target)
            app_name = target
        else:
            # Find app by package name
            applications = device.enumerate_applications()
            target_app = None
            
            for app in applications:
                if app.identifier == target and app.pid and app.pid > 0:
                    target_app = app
                    break
            
            if not target_app:
                return {
                    "status": "error",
                    "message": f"Unable to find running app: {target}"
                }
            
            pid = target_app.pid
            app_name = target_app.name
        
        # Attach to the process
        session = device.attach(pid)
        _bind_session_events(session)
        
        # 解析脚本内容
        script_content, error_response = _resolve_script_content(initial_script, script_file_path)
        if error_response:
            return error_response
        
        # If script content available, inject it immediately
        if script_content:
            try:
                await _load_script_with_global_buffer(session, script_content, output_file=output_file)
            except Exception as e:
                _frida_log(f"script load error: {e}")
                return {"status": "error", "message": str(e)}
        
        result = {
            "status": "success",
            "pid": pid,
            "target": target,
            "name": app_name if not target.isdigit() else target,
            "script_loaded": script_content is not None
        }
        
        result["message"] = "Attached successfully."
        
        return result
        
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


@app.tool()
async def spawn(
    package_name: str,
    initial_script: Optional[str] = None,
    script_file_path: Optional[str] = None,
    output_file: Optional[str] = None
) -> Dict[str, Any]:
    """
    拉起应用（挂起态）并附加，可选在恢复前注入脚本。

    Args:
      - package_name: 应用包名
      - initial_script: 可选注入的 Frida JS 代码字符串
      - script_file_path: 可选注入的 JS 文件绝对路径（优先于 initial_script）
      - output_file: 可选的本地电脑文件路径，用于保存 hook 输出（非安卓设备路径）

    Returns:
      - {status, pid, package, script_loaded, message}
    """
    global session
    
    # Clean up old session if exists
    if session:
        try:
            session.detach()
        except:
            pass  # Session might already be disconnected
        session = None
    
    # Ensure device is connected
    if not await ensure_device_connected():
        return {
            "status": "error",
            "message": "Failed to connect to device. Ensure frida-server is running."
        }
    
    try:
        # Spawn the app in suspended state
        pid = device.spawn(package_name)
        session = device.attach(pid)
        _bind_session_events(session)
        
        # 解析脚本内容
        script_content, error_response = _resolve_script_content(initial_script, script_file_path)
        if error_response:
            return error_response
        
        # If script content available, inject it before resuming
        if script_content:
            try:
                await _load_script_with_global_buffer(session, script_content, init_delay_seconds=0.1, output_file=output_file)
            except Exception as e:
                _frida_log(f"script load error: {e}")
                return {"status": "error", "message": str(e)}
        
        # Resume the app
        device.resume(pid)
        
        # No post-resume wait; logs are collected asynchronously in global buffer
        
        result = {
            "status": "success",
            "pid": pid,
            "package": package_name,
            "script_loaded": script_content is not None
        }
        
        result["message"] = "App spawned successfully."
        
        return result
        
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }





if __name__ == "__main__":
    app.run()