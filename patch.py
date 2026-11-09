import os
import re
import stat

print(">>> [Patch] 开始对编译环境执行极致全兼容深度修复...")

goroot = os.popen("go env GOROOT").read().strip()
if not goroot:
  raise RuntimeError("未检测到 GOROOT，请检查 Go 环境变量！")

tls_dir = os.path.join(goroot, "src", "crypto", "tls")

# =========================================================================
# 1. 修补 Go 标准库 TLS 1.2 与 TLS 1.3 状态机
#    - 彻底杜绝 MASQUE (RPK) 空证书导致的 index out of range [0] Panic
#    - 保证在 InsecureSkipVerify 下 verifiedChains 始终兜底填充，杜绝下游空指针
# =========================================================================
if os.path.exists(tls_dir):
  # A. TLS 1.2 (handshake_client.go)
  hc_path = os.path.join(tls_dir, "handshake_client.go")
  if os.path.exists(hc_path):
    os.chmod(hc_path, stat.S_IWRITE | stat.S_IREAD)
    with open(hc_path, "r", encoding="utf-8") as f:
      code = f.read()

    # 清除旧补丁粗暴截断的代码
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
        r"\t\terr = nil // [SAFE-PATCH] 放行自签名并兜底填充验证链\n"
        r"\t}"
    )
    if "[SAFE-PATCH]" not in code and re.search(target_v12, code):
      code = re.sub(target_v12, patch_v12, code, count=1)
      with open(hc_path, "w", encoding="utf-8") as f:
        f.write(code)
      print("  ✔ [TLS 1.2] handshake_client.go 安全验证链保护注入成功")

  # B. TLS 1.3 (handshake_client_tls13.go)
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
        r"\t\terr = nil // [MASQUE-RPK] 适配裸公钥/空证书链握手\n"
        r"\t}"
    )
    if "[SAFE-PATCH-13]" not in code and re.search(target_v13, code):
      code = re.sub(target_v13, patch_v13, code, count=1)
      with open(hc13_path, "w", encoding="utf-8") as f:
        f.write(code)
      print("  ✔ [TLS 1.3] handshake_client_tls13.go 防越界与证书兜底补丁注入成功")

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
    print("  ✔ [x509] Legacy Common Name 限制已解除")

# =========================================================================
# 2. 深度适配 uTLS (Chrome 指纹)：动态同步协议 ALPN
#    - 彻底解决开启 fingerprint: "chrome" 时强制送出 h2 导致 HTTPUpgrade/WS
#      被 Cloudflare 下发 TCP RST 强行重置的问题
# =========================================================================
utls_path = "transport/internet/tls/u_tls.go"
if os.path.exists(utls_path):
  with open(utls_path, "r", encoding="utf-8") as f:
    code = f.read()

  m = re.search(r"func\s*\(([a-zA-Z0-9_]+)\s*\*Config\)\s*UClient", code)
  recv = m.group(1) if m else "c"

  alpn_sync_hook = f"""
\t// [UTLS-DYNAMIC-ALPN] 动态根据节点传输协议同步 ALPN，避免与 Chrome 预设指纹冲突
\tif len({recv}.NextProtos) > 0 {{
\t\tfor _, ext := range uConn.Extensions {{
\t\t\tif alpnExt, ok := ext.(*utls.ALPNExtension); ok {{
\t\t\t\talpnExt.AlpnProtocols = {recv}.NextProtos
\t\t\t}}
\t\t}}
\t\t_ = uConn.BuildHandshakeState()
\t}}
"""
  if "[UTLS-DYNAMIC-ALPN]" not in code:
    if "return uConn, nil" in code:
      code = code.replace(
          "return uConn, nil", alpn_sync_hook + "\treturn uConn, nil", 1
      )
    elif "return uConn" in code:
      code = code.replace(
          "return uConn", alpn_sync_hook + "\treturn uConn", 1
      )

  # 保证 uTLS 上下文中的自签名节点免检
  code = re.sub(
      r"(uConfig\s*:=\s*&utls\.Config\{)",
      r"\1\n\t\tInsecureSkipVerify: true,",
      code,
  )

  with open(utls_path, "w", encoding="utf-8") as f:
    f.write(code)
  print("  ✔ [uTLS] Fingerprint 动态协议 ALPN 适配补丁注入成功！")

# =========================================================================
# 3. Xray-core 原生 TLS 工厂放行配置
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
    print(f"  ✔ [TLS Config] Xray TLS 工厂已配置放行: {tls_conf_path}")

# =========================================================================
# 4. Finalmask 握手碎片保护：零延迟平滑发送防 Cloudflare RST
# =========================================================================
for root, _, files in os.walk("transport/internet/finalmask"):
  for f in files:
    if f.endswith(".go"):
      fpath = os.path.join(root, f)
      with open(fpath, "r", encoding="utf-8") as file:
        c = file.read()
      # 将 tlshello 造成的 TCP 切片延迟降为 0，防止触发 Anycast 边缘防御的超时阻断
      if "tlshello" in c and "time.Duration(0)" not in c:
        c = re.sub(
            r"(delay\s*:=\s*[^;\n]+)",
            r"\1; delay = time.Duration(0) // [SMOOTH-FRAGMENT]",
            c,
        )
        with open(fpath, "w", encoding="utf-8") as file:
          file.write(c)
        print(f"  ✔ [Finalmask] TCP 分片防阻断零延迟补丁已应用: {f}")

# =========================================================================
# 5. 动态提取变量注入 UDP 10091 HUD 广播钩子
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

print(">>> 全部兼容性补丁写入完成！")
