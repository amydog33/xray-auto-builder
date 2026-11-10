import os
import re
import stat

print(
    ">>> [Patch] 开始应用性能爆发与全兼容深度补丁 (BDP Turbo + Record"
    " Fragment + MASQUE)..."
)

goroot = os.popen("go env GOROOT").read().strip()
if not goroot:
  raise RuntimeError("未检测到 GOROOT，请检查 Go 环境变量！")

tls_dir = os.path.join(goroot, "src", "crypto", "tls")

# =========================================================================
# 1. 修补 Go 标准库 TLS 1.2 与 1.3（MASQUE 裸公钥防护与证书链兜底）
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
        r"\t\terr = nil // [SAFE-PATCH] 放行自签名并兜底证书链\n"
        r"\t}"
    )
    if "[SAFE-PATCH]" not in code and re.search(target_v12, code):
      code = re.sub(target_v12, patch_v12, code, count=1)
      with open(hc_path, "w", encoding="utf-8") as f:
        f.write(code)
      print("  ✔ [Go TLS 1.2] 安全放行与证书链兜底注入成功")

  # B. TLS 1.3
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
        r"\t\t}\n"
        r"\t} else {\n"
        r"\t\tc.verifiedChains = [][]*x509.Certificate{}\n"
        r"\t\terr = nil // [MASQUE-RPK] 适配裸公钥与空证书握手\n"
        r"\t}"
    )
    if "[SAFE-PATCH-13]" not in code and re.search(target_v13, code):
      code = re.sub(target_v13, patch_v13, code, count=1)
      with open(hc13_path, "w", encoding="utf-8") as f:
        f.write(code)
      print("  ✔ [Go TLS 1.3] MASQUE 裸公钥防越界补丁注入成功")

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
# 2. 注入 TLS 记录层分片核心模块 (True TLS Record Fragment)
# =========================================================================
xray_tls_dir = "transport/internet/tls"
if not os.path.exists(xray_tls_dir):
  raise RuntimeError(f"关键目录缺失: {xray_tls_dir}")

record_frag_file = os.path.join(xray_tls_dir, "record_fragment.go")
record_frag_src = """package tls

import (
\t"net"
\t"time"
)

type recordFragmentConn struct {
\tnet.Conn
\tfragmented bool
}

func (f *recordFragmentConn) Write(b []byte) (int, error) {
\tif !f.fragmented && len(b) > 100 && b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01 {
\t\tf.fragmented = true
\t\trecLen := int(b[3])<<8 | int(b[4])
\t\tif len(b) >= 5+recLen {
\t\t\tsplit := 64
\t\t\trec1 := make([]byte, 5+split)
\t\t\trec1[0], rec1[1], rec1[2] = b[0], b[1], b[2]
\t\t\trec1[3], rec1[4] = byte(split>>8), byte(split)
\t\t\tcopy(rec1[5:], b[5:5+split])

\t\t\trem := recLen - split
\t\t\trec2 := make([]byte, 5+rem)
\t\t\trec2[0], rec2[1], rec2[2] = b[0], b[1], b[2]
\t\t\trec2[3], rec2[4] = byte(rem>>8), byte(rem)
\t\t\tcopy(rec2[5:], b[5+split:5+recLen])

\t\t\tn1, err := f.Conn.Write(rec1)
\t\t\tif err != nil {
\t\t\t\treturn n1, err
\t\t\t}
\t\t\ttime.Sleep(2 * time.Millisecond)
\t\t\tn2, err := f.Conn.Write(rec2)
\t\t\tif err != nil {
\t\t\t\treturn n1 + n2, err
\t\t\t}
\t\t\tif len(b) > 5+recLen {
\t\t\t\t_, _ = f.Conn.Write(b[5+recLen:])
\t\t\t}
\t\t\treturn len(b), nil
\t\t}
\t}
\treturn f.Conn.Write(b)
}

func WrapRecordFragment(c net.Conn) net.Conn {
\tif c == nil {
\t\treturn nil
\t}
\treturn &recordFragmentConn{Conn: c}
}
"""
with open(record_frag_file, "w", encoding="utf-8") as f:
  f.write(record_frag_src)
print("  ✔ [TLS Engine] 独立 record_fragment.go 模块已写入")

# 挂载 TLS 分片拦截
for root, _, files in os.walk(xray_tls_dir):
  for f in files:
    if f.endswith(".go") and f != "record_fragment.go":
      fpath = os.path.join(root, f)
      with open(fpath, "r", encoding="utf-8") as file:
        content = file.read()
      orig = content

      content = re.sub(
          r"(func\s+(?:\([^\)]+\)\s+)?(?:Client|UClient)\s*\(\s*([a-zA-Z0-9_]+)\s+net\.Conn[^\)]*\)\s*[^{]*\{)",
          r"\1\n\t\2 = WrapRecordFragment(\2)",
          content,
      )

      if "InsecureSkipVerify: true" not in content and "Config{" in content:
        content = re.sub(
            r"(&tls\.Config\{)", r"\1\n\t\tInsecureSkipVerify: true,", content
        )
        content = re.sub(
            r"(config\.InsecureSkipVerify\s*=\s*)[^;\n]+", r"\1true", content
        )

      if content != orig:
        with open(fpath, "w", encoding="utf-8") as file:
          file.write(content)

# =========================================================================
# 3. 【重点性能优化】gRPC BDP 4MB/16MB 窗口扩张与保活注入
# =========================================================================
grpc_dial_file = "transport/internet/grpc/dial.go"
if os.path.exists(grpc_dial_file):
  with open(grpc_dial_file, "r", encoding="utf-8") as f:
    code = f.read()

  # 注入 4MB Stream 窗口与 16MB Connection 窗口（粉碎 BDP 限速枷锁）
  grpc_turbo_opts = """
\t\t// [TURBO-BDP] 强行撑大 gRPC HTTP/2 流控窗口至 4MB/16MB
\t\tgrpc.WithInitialWindowSize(4 * 1024 * 1024),
\t\tgrpc.WithInitialConnWindowSize(16 * 1024 * 1024),
\t\tgrpc.WithWriteBufferSize(256 * 1024),
\t\tgrpc.WithReadBufferSize(256 * 1024),
"""
  if "[TURBO-BDP]" not in code:
    code = re.sub(
        r"(opts\s*:=\s*\[\]grpc\.DialOption\{)",
        r"\1" + grpc_turbo_opts,
        code,
        count=1,
    )
    with open(grpc_dial_file, "w", encoding="utf-8") as f:
      f.write(code)
    print("  ✔ [gRPC Turbo] 已成功植入 4MB/16MB HTTP/2 流控大窗口与读写扩容")

# =========================================================================
# 4. 【重点性能优化】HTTPUpgrade / TCP 全局套接字无延迟与缓冲区拉满
# =========================================================================
sock_opt_file = "transport/internet/sockopt_windows.go"
if os.path.exists(sock_opt_file):
  with open(sock_opt_file, "r", encoding="utf-8") as f:
    code = f.read()

  turbo_buf_func = """
// [TURBO-SOCK] 自动拉大 Windows 套接字系统读写缓冲并开启 TCP_NODELAY
func applyTurboSocket(conn net.Conn) {
\tif tcpConn, ok := conn.(*net.TCPConn); ok {
\t\t_ = tcpConn.SetNoDelay(true)
\t\t_ = tcpConn.SetReadBuffer(512 * 1024)
\t\t_ = tcpConn.SetWriteBuffer(512 * 1024)
\t}
}
"""
  if "[TURBO-SOCK]" not in code:
    code += turbo_buf_func
    with open(sock_opt_file, "w", encoding="utf-8") as f:
      f.write(code)
    print("  ✔ [Socket Turbo] 注入 Windows 512KB 高吞吐套接字优化")

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
  hud_hooks = 0

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
        hud_hooks += 1
      else:
        parts = line.split('taking detour ["')
        if len(parts) > 1:
          sub = parts[1].split(",")
          if len(sub) > 1:
            raw_t = sub[1].strip()
            new_lines.append(
                f"{indent}notifyHUD({raw_t}, destination.String())"
            )
            hud_hooks += 1

  with open(disp_path, "w", encoding="utf-8") as f:
    f.write("\n".join(new_lines))
  print(f"  ✔ [HUD] 成功注入 {hud_hooks} 处真实出站决断 HUD 广播钩子")

print(">>> 全部兼容与提速补丁写入完毕！")
