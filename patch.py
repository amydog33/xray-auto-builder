import os
import re
import stat

# 1. 解除只读并短路 Go 标准库底层 TLS 与 x509 校验（自签/老旧 CN 证书无条件放行）
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
          print(f"[Patch 1/3] Go TLS 握手放行成功: {f}")

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
  print("[Patch 1/3] Go x509: Legacy Common Name 校验限制解除！")

# 2. 移除 Xray 自身配置阶段对 allowInsecure 的阻断拦截
for root, _, files in os.walk("."):
  for file in files:
    if file.endswith(".go"):
      fpath = os.path.join(root, file)
      with open(fpath, "r", encoding="utf-8", errors="ignore") as file:
        c = file.read()
      if "allowInsecure" in c and "has been removed" in c:
        c = re.sub(
            r'return nil, newError\([^\)]*allowInsecure[^\)]*\)',
            "config.InsecureSkipVerify = true",
            c,
        )
        with open(fpath, "w", encoding="utf-8") as file:
          file.write(c)
        print(f"[Patch 2/3] Xray-core 配置拦截移除: {fpath}")

# 3. 注入 UDP 127.0.0.1:10091 内存广播钩子
disp_path = "app/dispatcher/default.go"
if os.path.exists(disp_path):
  with open(disp_path, "r", encoding="utf-8") as file:
    disp = file.read()

  if 'stdnet "net"' not in disp:
    disp = disp.replace("import (", 'import (\n\tstdnet "net"', 1)

  # 在文件末尾追加 notifyHUD 函数，确保 stdnet 始终被显式引用，解决未使用报错
  hud_func = """

// notifyHUD 内存域名广播钩子
func notifyHUD(dest net.Destination) {
	if dest.Address != nil {
		go func(target string) {
			if conn, err := stdnet.Dial("udp", "127.0.0.1:10091"); err == nil {
				conn.Write([]byte(target))
				conn.Close()
			}
		}(dest.String())
	}
}
"""
  disp += hud_func

  # 动态匹配 Dispatch 与 DispatchLink 的具体参数名并植入调用
  match_dispatch = re.search(
      r"func \(d \*DefaultDispatcher\) Dispatch\([^,]+,\s*([a-zA-Z0-9_]+)\s+net\.Destination",
      disp,
  )
  if match_dispatch:
    pname = match_dispatch.group(1)
    disp = re.sub(
        r"(func \(d \*DefaultDispatcher\) Dispatch\([^{]+\{)",
        r"\1\n\tnotifyHUD(" + pname + ")",
        disp,
        count=1,
    )
    print(f"[Patch 3/3] 成功挂钩 Dispatch (参数: {pname})")

  match_link = re.search(
      r"func \(d \*DefaultDispatcher\) DispatchLink\([^,]+,\s*([a-zA-Z0-9_]+)\s+net\.Destination",
      disp,
  )
  if match_link:
    pname_link = match_link.group(1)
    disp = re.sub(
        r"(func \(d \*DefaultDispatcher\) DispatchLink\([^{]+\{)",
        r"\1\n\tnotifyHUD(" + pname_link + ")",
        disp,
        count=1,
    )
    print(f"[Patch 3/3] 成功挂钩 DispatchLink (参数: {pname_link})")

  with open(disp_path, "w", encoding="utf-8") as file:
    file.write(disp)
  print("[Patch 3/3] UDP 127.0.0.1:10091 内存广播注入完成！")
