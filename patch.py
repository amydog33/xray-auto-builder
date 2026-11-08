import os
import re
import stat

print(">>> [Patch] 开始对编译环境执行精准修复...")

goroot = os.popen("go env GOROOT").read().strip()
if not goroot:
  raise RuntimeError("未检测到 GOROOT，请检查 Go 环境变量！")

# ==========================================
# 1. 修复 Go 底层 TLS：赋值 peerCertificates 后放行自签
# ==========================================
handshake_client = os.path.join(
    goroot, "src", "crypto", "tls", "handshake_client.go"
)
if os.path.exists(handshake_client):
  os.chmod(handshake_client, stat.S_IWRITE | stat.S_IREAD)
  with open(handshake_client, "r", encoding="utf-8") as f:
    code = f.read()

  # 清理旧补丁中在函数入口盲目 return nil 的错误逻辑
  code = re.sub(
      r"(func \(c \*Conn\) verifyServerCertificate\([^\)]*\) error \{\s*)\n\treturn nil[^\n]*\n",
      r"\1",
      code,
  )

  # 在 c.peerCertificates = certs 之后立即 return nil
  # 既保证 peerCertificates[0] 有公钥供 TLS 1.3 验签，又彻底放行自签名证书
  target = "c.peerCertificates = certs"
  patch_hook = (
      "c.peerCertificates = certs\n\treturn nil // [MASQUE] 填充证书公钥后放行自签"
  )
  if target in code and "[MASQUE]" not in code:
    code = code.replace(target, patch_hook, 1)
    with open(handshake_client, "w", encoding="utf-8") as f:
      f.write(code)
    print("  ✔ Go TLS verifyServerCertificate 证书提取并放行补丁注入成功！")
  elif "[MASQUE]" in code:
    print("  ✔ Go TLS 补丁此前已处于正确状态")

# 解除 Legacy Common Name 校验限制
x509_verify = os.path.join(goroot, "src", "crypto", "x509", "verify.go")
if os.path.exists(x509_verify):
  os.chmod(x509_verify, stat.S_IWRITE | stat.S_IREAD)
  with open(x509_verify, "r", encoding="utf-8") as f:
    code = f.read()
  if "legacy Common Name" in code:
    code = re.sub(
        r"return CertificateInvalidError\{[^\}]*legacy Common Name[^\}]*\}",
        "return nil",
        code,
    )
    with open(x509_verify, "w", encoding="utf-8") as f:
      f.write(code)
    print("  ✔ Go x509 Legacy Common Name 限制已解除")

# ==========================================
# 2. Xray-core TLS 工厂放行
# ==========================================
tls_conf_path = "transport/internet/tls/config.go"
if os.path.exists(tls_conf_path):
  with open(tls_conf_path, "r", encoding="utf-8") as f:
    code = f.read()
  if "InsecureSkipVerify: true" not in code:
    code = re.sub(
        r"(&tls\.Config\{)", r"\1\n\t\tInsecureSkipVerify: true,", code
    )
    code = re.sub(
        r"config\.InsecureSkipVerify = [^;\n]+",
        "config.InsecureSkipVerify = true",
        code,
    )
    with open(tls_conf_path, "w", encoding="utf-8") as f:
      f.write(code)
    print(f"  ✔ Xray TLS 工厂已配置放行: {tls_conf_path}")

# ==========================================
# 3. 动态提取变量注入 UDP 10091 HUD 广播钩子
# ==========================================
disp_path = "app/dispatcher/default.go"
if os.path.exists(disp_path):
  with open(disp_path, "r", encoding="utf-8") as f:
    content = f.read()

  if 'stdnet "net"' not in content:
    content = content.replace("import (", 'import (\n\tstdnet "net"', 1)

  hud_func = """
// notifyHUD 内存广播钩子
func notifyHUD(tag string, dest string) {
\tif dest != "" {
\t\tgo func(msg string) {
\t\t\tif conn, err := stdnet.Dial("udp", "127.0.0.1:10091"); err == nil {
\t\t\t\tconn.Write([]byte(msg))
\t\t\t\tconn.Close()
\t\t\t}
\t\t}(tag + "|" + dest)
\t}
}
"""
  if "func notifyHUD" not in content:
    content += hud_func

  lines = content.splitlines()
  new_lines = []
  hook_count = 0

  for line in lines:
    new_lines.append(line)
    if "taking detour" in line and not line.strip().startswith("//"):
      indent = line[: len(line) - len(line.lstrip())]
      m_vars = re.search(
          r'taking detour \[\",\s*([^,]+),\s*\"\] for \[\",\s*([^,\)]+)', line
      )
      if m_vars:
        t_var = m_vars.group(1).strip()
        d_var = m_vars.group(2).strip()
        d_call = (
            f"{d_var}.String()" if not d_var.endswith(".String()") else d_var
        )
        new_lines.append(f"{indent}notifyHUD({t_var}, {d_call})")
        hook_count += 1
      else:
        parts = line.split('taking detour ["')
        if len(parts) > 1:
          sub = parts[1].split(",")
          if len(sub) > 1:
            raw_t = sub[1].strip()
            new_lines.append(f"{indent}notifyHUD({raw_t}, destination.String())")
            hook_count += 1

  with open(disp_path, "w", encoding="utf-8") as f:
    f.write("\n".join(new_lines))
  print(f"  ✔ 成功注入 {hook_count} 处真实出站决断 HUD 广播钩子")

print(">>> 全部补丁写入完成！")
