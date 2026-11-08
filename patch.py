import os
import re

# 1. 终极放行：短路 Go 标准库底层 TLS 证书校验
goroot = os.popen("go env GOROOT").read().strip()
tls_client = os.path.join(
    goroot, "src", "crypto", "tls", "handshake_client.go"
)
if os.path.exists(tls_client):
  with open(tls_client, "r", encoding="utf-8") as f:
    code = f.read()
  pattern = (
      r"(func \(c \*clientHandshakeState[^\)]*\)"
      r" verifyServerCertificate\([^\)]*\) error \{)"
  )
  code = re.sub(
      pattern,
      r"\1\n\treturn nil // Force allow all self-signed certs\n",
      code,
      count=1,
  )
  with open(tls_client, "w", encoding="utf-8") as f:
    f.write(code)
  print("[Patch 1/3] Go TLS 底层证书校验已放行！")

# 2. 移除 Xray 自身配置阶段对 allowInsecure 的报错拦截
for root, _, files in os.walk("."):
  for file in files:
    if file.endswith(".go"):
      fpath = os.path.join(root, file)
      with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
        c = f.read()
      if "allowInsecure" in c and "has been removed" in c:
        c = re.sub(
            r'return nil, newError\([^\)]*allowInsecure[^\)]*\)',
            "config.InsecureSkipVerify = true",
            c,
        )
        with open(fpath, "w", encoding="utf-8") as f:
          f.write(c)
        print(f"[Patch 2/3] 移除配置拦截: {fpath}")

# 3. 注入 UDP 127.0.0.1:10091 内存广播钩子
disp_path = "app/dispatcher/default.go"
if os.path.exists(disp_path):
  with open(disp_path, "r", encoding="utf-8") as f:
    disp = f.read()

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

  with open(disp_path, "w", encoding="utf-8") as f:
    f.write(disp)
  print("[Patch 3/3] 127.0.0.1:10091 内存流广播钩子注入成功！")
