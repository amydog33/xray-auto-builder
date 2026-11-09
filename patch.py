import os
import re
import stat

print(">>> [Patch] 开始对编译环境执行精准全兼容修复...")

goroot = os.popen("go env GOROOT").read().strip()
if not goroot:
  raise RuntimeError("未检测到 GOROOT，请检查 Go 环境变量！")

tls_dir = os.path.join(goroot, "src", "crypto", "tls")

# =========================================================================
# 1. 修补 Go 标准库 TLS 1.2 与 TLS 1.3 状态机（防 MASQUE RPK Panic 与自签放行）
# =========================================================================
if os.path.exists(tls_dir):
  # A. TLS 1.2
  hc_path = os.path.join(tls_dir, "handshake_client.go")
  if os.path.exists(hc_path):
    os.chmod(hc_path, stat.S_IWRITE | stat.S_IREAD)
    with open(hc_path, "r", encoding="utf-8") as f:
      code = f.read()

    code = re.sub(
        r"c\.peerCertificates = certs\s*\n\treturn nil[^\n]*\n",
        "c.peerCertificates = certs\n",
        code,
    )

    target_v12 = r"(c\.verifiedChains,\s*err\s*=\s*certs\[0\]\.Verify\(opts\))"
    patch_v12 = (
        r"\1\n"
        r"\tif err != nil {\n"
        r"\t\tif len(certs) > 0 {\n"
        r"\t\t\tc.verifiedChains = [][]*x509.Certificate{certs}\n"
        r"\t\t}\n"
        r"\t\terr = nil // [SAFE-PATCH] 放行自签并兜底证书链\n"
        r"\t}"
    )
    if "[SAFE-PATCH]" not in code and re.search(target_v12, code):
      code = re.sub(target_v12, patch_v12, code, count=1)
      with open(hc_path, "w", encoding="utf-8") as f:
        f.write(code)
      print("  ✔ [Go TLS 1.2] 安全放行补丁应用成功")

  # B. TLS 1.3 (彻底解决 MASQUE 空证书越界)
  hc13_path = os.path.join(tls_dir, "handshake_client_tls13.go")
  if os.path.exists(hc13_path):
    os.chmod(hc13_path, stat.S_IWRITE | stat.S_IREAD)
    with open(hc13_path, "r", encoding="utf-8") as f:
      code = f.read()

    target_v13 = r"(c\.verifiedChains,\s*err\s*=\s*certs\[0\]\.Verify\(opts\))"
    patch_v13 = (
        r"\tif len(certs) > 0 {\n"
        r"\t\tc.verifiedChains, err = certs[0].Verify(opts)\n"
        r"\t\tif err != nil {\n"
        r"\t\t\tc.verifiedChains = [][]*x509.Certificate{certs}\n"
        r"\t\t\terr = nil // [SAFE-PATCH-13] TLS 1.3 兜底自签证书链\n"
        r"\t\t}\n"
        r"\t} else {\n"
        r"\t\tc.verifiedChains = [][]*x509.Certificate{}\n"
        r"\t\terr = nil // [MASQUE-RPK] 适配空证书链/裸公钥握手\n"
        r"\t}"
    )
    if "[SAFE-PATCH-13]" not in code and re.search(target_v13, code):
      code = re.sub(target_v13, patch_v13, code, count=1)
      with open(hc13_path, "w", encoding="utf-8") as f:
        f.write(code)
      print("  ✔ [Go TLS 1.3] MASQUE 裸公钥防越界补丁应用成功")

# C. 解除 Legacy Common Name 校验限制
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
    print("  ✔ [Go x509] Legacy Common Name 限制已解除")

# =========================================================================
# 2. 精准定位 transport/internet/tls/tls.go：
#    - 注入 Auto-Fragment (ClientHello 自动拆包，彻底免疫防火墙 SNI RST)
#    - 包装 Client 与 UClient (Chrome 等所有指纹)
# =========================================================================
tls_main_file = "transport/internet/tls/tls.go"
if not os.path.exists(tls_main_file):
  raise RuntimeError(f"关键文件缺失: {tls_main_file}")

with open(tls_main_file, "r", encoding="utf-8") as f:
  code = f.read()

fragment_wrapper = """

// [AUTO-FRAGMENT] 底层自动分片包装器：将 ClientHello 拆包避开防火墙 SNI RST
type autoFragmentConn struct {
\tnet.Conn
\tfragmented bool
}

func (f *autoFragmentConn) Write(b []byte) (int, error) {
\tif !f.fragmented && len(b) > 64 && b[0] == 0x16 {
\t\tf.fragmented = true
\t\tsplit := 64
\t\tn1, err := f.Conn.Write(b[:split])
\t\tif err != nil {
\t\t\treturn n1, err
\t\t}
\t\ttime.Sleep(5 * time.Millisecond) // 强制让底层网卡发出首包（首包不含 SNI 扩展）
\t\tn2, err := f.Conn.Write(b[split:])
\t\treturn n1 + n2, err
\t}
\treturn f.Conn.Write(b)
}

func wrapAutoFragment(c net.Conn) net.Conn {
\tif c == nil {
\t\treturn nil
\t}
\treturn &autoFragmentConn{Conn: c}
}
"""

if "[AUTO-FRAGMENT]" not in code:
  code += fragment_wrapper

  # 1. 包装标准 TLS Client(c net.Conn, config *tls.Config)
  code = re.sub(
      r"(func Client\s*\(\s*c\s+net\.Conn,\s*config\s+\*tls\.Config\s*\)\s*net\.Conn\s*\{)",
      r"\1\n\tc = wrapAutoFragment(c)",
      code,
      count=1,
  )

  # 2. 包装 uTLS 指纹客户端 UClient(c net.Conn, ...)
  code = re.sub(
      r"(func UClient\s*\(\s*c\s+net\.Conn[^\)]*\)\s*net\.Conn\s*\{)",
      r"\1\n\tc = wrapAutoFragment(c)",
      code,
      count=1,
  )

with open(tls_main_file, "w", encoding="utf-8") as f:
  f.write(code)
print("  ✔ [Xray TLS Engine] Auto-Fragment 自动分片机制已成功植入 tls.go！")

# =========================================================================
# 3. Xray 原生 TLS 配置放行 (transport/internet/tls/config.go)
# =========================================================================
tls_conf_path = "transport/internet/tls/config.go"
if os.path.exists(tls_conf_path):
  with open(tls_conf_path, "r", encoding="utf-8") as f:
    code = f.read()
  if "InsecureSkipVerify: true" not in code:
    code = re.sub(r"(&tls\.Config\{)", r"\1\n\t\tInsecureSkipVerify: true,", code)
    code = re.sub(
        r"config\.InsecureSkipVerify = [^;\n]+",
        "config.InsecureSkipVerify = true",
        code,
    )
    with open(tls_conf_path, "w", encoding="utf-8") as f:
      f.write(code)
    print("  ✔ [Xray Config] InsecureSkipVerify 强制放行注入完成")

# =========================================================================
# 4. 动态提取变量注入 UDP 10091 HUD 广播钩子
# =========================================================================
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
            new_lines.append(
                f"{indent}notifyHUD({raw_t}, destination.String())"
            )
            hook_count += 1

  with open(disp_path, "w", encoding="utf-8") as f:
    f.write("\n".join(new_lines))
  print(f"  ✔ [HUD] 成功注入 {hook_count} 处真实出站决断 HUD 广播钩子")

print(">>> 全部兼容性补丁写入完毕！")
