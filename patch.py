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
  with open(tls_conf_path, "r", encoding="utf-8") as file:
    code = file.read()
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

# 3. 动态从源码上下文提取真实变量名并注入广播钩子
disp_path = "app/dispatcher/default.go"
if os.path.exists(disp_path):
  with open(disp_path, "r", encoding="utf-8") as file:
    content = file.read()

  if 'stdnet "net"' not in content:
    content = content.replace("import (", 'import (\n\tstdnet "net"', 1)

  hud_func = """

// notifyHUD 内存广播钩子
func notifyHUD(tag string, dest string) {
	if dest != "" {
		go func(msg string) {
			if conn, err := stdnet.Dial("udp", "127.0.0.1:10091"); err == nil {
				conn.Write([]byte(msg))
				conn.Close()
			}
		}(tag + "|" + dest)
	}
}
"""
  if "func notifyHUD" not in content:
    content += hud_func

  lines = content.splitlines()
  new_lines = []
  hook_count = 0

  for line in lines:
    new_lines.append(line)
    # 精准定位包含 taking detour 的代码行
    if "taking detour" in line and not line.strip().startswith("//"):
      indent = line[: len(line) - len(line.lstrip())]
      # 动态从当前行 newError("taking detour [", VAR1, "] for [", VAR2, ... 提取真实变量名
      m_vars = re.search(r'taking detour \[\",\s*([^,]+),\s*\"\] for \[\",\s*([^,\)]+)', line)
      if m_vars:
        t_var = m_vars.group(1).strip()
        d_var = m_vars.group(2).strip()
        # 兼容变量本身自带 .String() 或为 net.Destination
        d_call = f"{d_var}.String()" if not d_var.endswith(".String()") else d_var
        new_lines.append(f"{indent}notifyHUD({t_var}, {d_call})")
        hook_count += 1
        print(f"[Patch 3/3] 动态匹配成功: tag={t_var}, dest={d_var}")
      else:
        # 如果格式有微调，从当前行的逗号参数列表直接按位置提取第一个参数
        parts = line.split('taking detour ["')
        if len(parts) > 1:
          sub = parts[1].split(',')
          if len(sub) > 1:
            raw_t = sub[1].strip()
            new_lines.append(f"{indent}notifyHUD(fmt.Sprint({raw_t}), destination.String())")
            hook_count += 1

  if hook_count == 0:
    raise RuntimeError("【中断】未能在源码中匹配到 taking detour 行！")

  with open(disp_path, "w", encoding="utf-8") as file:
    file.write("\n".join(new_lines))
  print(f"[Patch 3/3] 共注入 {hook_count} 处真实出站决断钩子！")

print(">>> 全部补丁写入完成！")
