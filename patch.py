import os
import re
import stat

print(">>> 开始注入底层补丁...")

# 1. 终极放行：短路 Go 标准库底层 TLS 与 x509 校验（自签/无 SAN 证书直接放行）
goroot = os.popen("go env GOROOT").read().strip()

# 1.1 遍历 crypto/tls 目录下的所有客户端握手逻辑，强制 verifyServerCertificate 返回 nil
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

# 1.2 放行 crypto/x509 中对 legacy Common Name / SAN 缺失的拦截报错
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

# 2. 移除 Xray 源码内部对 allowInsecure 的报错拦截，全局强制 InsecureSkipVerify = true
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
  with open(tls_conf_path, "w", encoding="utf-8") as f:
    f.write(code)
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

# 3. 注入带真实出站标签 (tag) 的 UDP 127.0.0.1:10091 内存广播钩子
disp_path = "app/dispatcher/default.go"
if os.path.exists(disp_path):
  with open(disp_path, "r", encoding="utf-8") as file:
    disp = file.read()

  if 'stdnet "net"' not in disp:
    disp = disp.replace("import (", 'import (\n\tstdnet "net"\n\t"fmt"', 1)

  # 写入升级版通知函数：广播 "tag|target"
  hud_func = """

// notifyHUD 内存广播钩子 (带真实出站 tag)
func notifyHUD(tag string, dest net.Destination) {
	if dest.Address != nil {
		go func(msg string) {
			if conn, err := stdnet.Dial("udp", "127.0.0.1:10091"); err == nil {
				conn.Write([]byte(msg))
				conn.Close()
			}
		}(tag + "|" + dest.String())
	}
}
"""
  if "func notifyHUD" not in disp:
    disp += hud_func

  # 挂钩到 Xray 确定出站 detour 的决断代码处
  pattern_detour = r'(newError\("taking detour \[\",\s*([a-zA-Z0-9_\.]+),\s*\"\] for \[\",\s*([a-zA-Z0-9_\.]+))'
  if re.search(pattern_detour, disp):
    disp = re.sub(
        pattern_detour,
        r"\1\n\tnotifyHUD(fmt.Sprint(\2), \3)",
        disp,
        count=1,
    )
    print("[Patch 3/3] 成功挂钩 Xray detour 真实出站决策点！")
  else:
    # 备用入口
    pattern_dispatch = r"func \(d \*DefaultDispatcher\) Dispatch\([^,]+,\s*([a-zA-Z0-9_]+)\s+net\.Destination"
    m = re.search(pattern_dispatch, disp)
    if m:
      pname = m.group(1)
      disp = re.sub(
          r"(func \(d \*DefaultDispatcher\) Dispatch\([^{]+\{)",
          r'\1\n\tnotifyHUD("proxy", ' + pname + ")",
          disp,
          count=1,
      )
      print("[Patch 3/3] 备用挂钩 Dispatch 成功！")

  with open(disp_path, "w", encoding="utf-8") as file:
    file.write(disp)
  print("[Patch 3/3] UDP 10091 带标签内存广播注入完成！")

print(">>> 全部补丁写入完成！")
