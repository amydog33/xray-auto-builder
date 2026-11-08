import os
import re
import stat

print(">>> 开始注入底层补丁...")

# 1. 短路 Go 标准库底层 TLS 与 x509 校验
goroot = os.popen("go env GOROOT").read().strip()
tls_dir = os.path.join(goroot, "src", "crypto", "tls")
if os.path.exists(tls_dir):
  for root, _, files in os.walk(tls_dir):
    for f in files:
      if f.startswith("handshake_client") and f.endswith(".go"):
        fpath = os.path.join(root, f)
        os.chmod(fpath, stat.S_IWRITE | stat.S_IREAD)
        with open(fpath, "r", encoding="utf-8") as file:
          code = file.read()
        pattern = (
            r"(func \([a-zA-Z0-9_* ]+\) verifyServerCertificate\([^\)]*\)"
            r" error \{)"
        )
        if re.search(pattern, code):
          code = re.sub(
              pattern,
              r"\1\n\treturn nil // Force allow all self-signed certs\n",
              code,
              count=1,
          )
          with open(fpath, "w", encoding="utf-8") as file:
            file.write(code)
          print(f"[Patch 1/3] Go TLS 放行成功: {f}")

x509_verify = os.path.join(goroot, "src", "crypto", "x509", "verify.go")
if os.path.exists(x509_verify):
  os.chmod(x509_verify, stat.S_IWRITE | stat.S_IREAD)
  with open(x509_verify, "r", encoding="utf-8") as file:
    code = file.read()
  code = re.sub(
      r"return CertificateInvalidError\{[^\}]*legacy Common Name[^\}]*\}",
      "return nil",
      code,
  )
  with open(x509_verify, "w", encoding="utf-8") as file:
    file.write(code)
  print("[Patch 1/3] Go x509: Legacy Common Name 校验限制已解除！")

# 2. 全局强制 InsecureSkipVerify = true
tls_conf_path = "transport/internet/tls/config.go"
if os.path.exists(tls_conf_path):
  with open(tls_conf_path, "r", encoding="utf-8") as f:
    code = f.read()
  code = re.sub(
      r"(&tls\.Config\{)", r"\1\n\t\tInsecureSkipVerify: true,", code
  )
  code = re.sub(
      r"config\.InsecureSkipVerify = [^;\n]+",
      "config.InsecureSkipVerify = true",
      code,
  )
  with open(tls_conf_path, "w", encoding="utf-8") as file:
    file.write(code)
  print(f"[Patch 2/3] Xray-core TLS 工厂强制放行: {tls_conf_path}")

for root, _, files in os.walk("."):
  for f in files:
    if f.endswith(".go"):
      fpath = os.path.join(root, f)
      with open(fpath, "r", encoding="utf-8", errors="ignore") as file:
        c = file.read()
      orig = c
      if "allowInsecure" in c and "has been removed" in c:
        c = re.sub(
            r'return nil, newError\([^\)]*allowInsecure[^\)]*\)',
            "config.InsecureSkipVerify = true",
            c,
        )
      if "InsecureSkipVerify:" in c:
        c = re.sub(
            r"InsecureSkipVerify:\s*(?:false|c\.AllowInsecure|config\.AllowInsecure|c\.InsecureSkipVerify)",
            "InsecureSkipVerify: true",
            c,
        )
      if c != orig:
        with open(fpath, "w", encoding="utf-8") as file:
          file.write(c)

# 3. 注入带真实出站标签的 UDP 10091 广播钩子（修复：Dispatch 和 DispatchLink 双挂钩）
disp_path = "app/dispatcher/default.go"
if os.path.exists(disp_path):
  with open(disp_path, "r", encoding="utf-8") as file:
    disp = file.read()

  if 'stdnet "net"' not in disp:
    disp = disp.replace("import (", 'import (\n\tstdnet "net"', 1)

  # 纯净的 notifyHUD 函数，严禁加任何无用前缀
  hud_func = """

// notifyHUD 内存广播钩子
func notifyHUD(tag interface{}, dest net.Destination) {
	if dest.Address != nil {
		go func(tStr, target string) {
			if conn, err := stdnet.Dial("udp", "127.0.0.1:10091"); err == nil {
				conn.Write([]byte(tStr + "|" + target))
				conn.Close()
			}
		}(toTagStr(tag), dest.String())
	}
}

func toTagStr(v interface{}) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return "proxy"
}
"""
  if "func notifyHUD" not in disp:
    disp += hud_func

  # 核心修复：对所有出现 taking detour 的地方全部注入（覆盖浏览器走的 DispatchLink）
  lines = disp.splitlines()
  new_lines = []
  hook_count = 0
  for line in lines:
    new_lines.append(line)
    if 'newError("taking detour [' in line:
      indent = line[: len(line) - len(line.lstrip())]
      if "destination.Tag" in line:
        new_lines.append(f"{indent}notifyHUD(destination.Tag, destination)")
        hook_count += 1
      elif "tag" in line:
        new_lines.append(f"{indent}notifyHUD(tag, destination)")
        hook_count += 1

  disp = "\n".join(new_lines)
  print(f"[Patch 3/3] 成功挂钩 {hook_count} 处决断点（已覆盖所有代理入站流量）！")

  with open(disp_path, "w", encoding="utf-8") as file:
    file.write(disp)

print(">>> 全部补丁写入完成！")
