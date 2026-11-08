import os
import re
import stat

# 1. 终极解法：解除只读并短路 Go 标准库底层 TLS 与 x509 校验
goroot = os.popen("go env GOROOT").read().strip()

# 1.1 遍历 crypto/tls 目录下的所有客户端握手逻辑，强制 verifyServerCertificate 返回 nil
tls_dir = os.path.join(goroot, "src", "crypto", "tls")
if os.path.exists(tls_dir):
  for root, _, files in os.walk(tls_dir):
    for f in files:
      if f.startswith("handshake_client") and f.endswith(".go"):
        fpath = os.path.join(root, f)
        # 解除只读属性
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
  # 移除 Common Name 校验失败时的阻断抛错
  code = re.sub(
      r"return CertificateInvalidError\{[^\}]*legacy Common Name[^\}]*\}",
      "return nil",
      code,
  )
  with open(x509_verify, "w", encoding="utf-8") as file:
    file.write(code)
  print("[Patch 1/3] Go x509: Legacy Common Name 校验限制已解除！")

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

  hook_code = (
      "\n\tif dest.Address != nil {\n"
      "\t\tgo func(target string) {\n"
      '\t\t\tif conn, err := stdnet.Dial("udp", "127.0.0.1:10091"); err == nil'
      " {\n"
      "\t\t\t\tconn.Write([]byte(target))\n"
      "\t\t\t\tconn.Close()\n"
      "\t\t\t}\n"
      "\t\t}(dest.String())\n"
      "\t}\n"
  )

  pattern = (
      r"(func \(d \*DefaultDispatcher\) Dispatch\(ctx context\.Context, dest"
      r" net\.Destination\) \(\*transport\.Link, error\) \{)"
  )
  disp = re.sub(pattern, r"\1" + hook_code, disp, count=1)

  with open(disp_path, "w", encoding="utf-8") as file:
    file.write(disp)
  print("[Patch 3/3] 127.0.0.1:10091 内存流广播钩子注入成功！")
