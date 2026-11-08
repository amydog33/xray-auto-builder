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

# 3. 注入 UDP 10091 双保险广播钩子
disp_path = "app/dispatcher/default.go"
if os.path.exists(disp_path):
  with open(disp_path, "r", encoding="utf-8") as file:
    disp = file.read()

  if 'stdnet "net"' not in disp:
    disp = disp.replace("import (", 'import (\n\tstdnet "net"\n\t"fmt"', 1)

  hud_func = """

// notifyHUD 内存广播钩子
func notifyHUD(tag interface{}, dest net.Destination) {
	if dest.Address != nil {
		go func(tStr, target string) {
			if conn, err := stdnet.Dial("udp", "127.0.0.1:10091"); err == nil {
				conn.Write([]byte(tStr + "|" + target))
				conn.Close()
			}
		}(fmt.Sprint(tag), dest.String())
	}
}
"""
  if "func notifyHUD" not in disp:
    disp += hud_func

  # 方案 A：通用正则动态捕获 taking detour 那一行的真实 tag 变量与 destination 变量
  pattern_detour = r'(taking detour \[\",\s*([^,]+),\s*\"\] for \[\",\s*([^,\)]+))'
  m_detour = re.search(pattern_detour, disp)
  if m_detour:
    tag_var = m_detour.group(2)
    dest_var = m_detour.group(3)
    disp = re.sub(
        pattern_detour,
        rf'\1\n\tnotifyHUD({tag_var}, {dest_var})',
        disp,
        count=1,
    )
    print(f"[Patch 3/3] 成功挂钩 detour 决断点: tag={tag_var}, dest={dest_var}")

  # 方案 B（双保险）：在 Dispatch 与 DispatchLink 入口始终植入保底广播，杜绝断流
  match_dispatch = re.search(
      r"func \(d \*DefaultDispatcher\) Dispatch\([^,]+,\s*([a-zA-Z0-9_]+)\s+net\.Destination",
      disp,
  )
  if match_dispatch:
    pname = match_dispatch.group(1)
    disp = re.sub(
        r"(func \(d \*DefaultDispatcher\) Dispatch\([^{]+\{)",
        rf'\1\n\tnotifyHUD("ingress", {pname})',
        disp,
        count=1,
    )

  match_link = re.search(
      r"func \(d \*DefaultDispatcher\) DispatchLink\([^,]+,\s*([a-zA-Z0-9_]+)\s+net\.Destination",
      disp,
  )
  if match_link:
    pname_link = match_link.group(1)
    disp = re.sub(
        r"(func \(d \*DefaultDispatcher\) DispatchLink\([^{]+\{)",
        rf'\1\n\tnotifyHUD("ingress", {pname_link})',
        disp,
        count=1,
    )

  with open(disp_path, "w", encoding="utf-8") as file:
    file.write(disp)
  print("[Patch 3/3] UDP 10091 双保险内存广播注入完成！")

print(">>> 全部补丁写入完成！")
