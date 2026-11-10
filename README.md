# ESPHome NPS-Client 组件说明

## 1. 组件介绍

本项目是 ESPHome 的外部组件，让 ESP32 以 npc（nps 客户端）身份直接连接 nps 服务器，通过服务器上配置的 TCP 隧道把公网流量转发到 ESP32 上的本地服务。

与在局域网网关跑 npc 不同，本组件把整个 nps 客户端协议跑在 ESP32 上，设备可以独立直连公网 nps 服务器，无需任何中间主机，

你无需再为了零星或分散的节点，专门为其部署和维护一个局域网端的npc转发服务

- 包含两个组件：

  - `nps_client`​：适配[djylb/nps](https://github.com/djylb/nps)的二开版本
  - `nps_client_origin`​：适配原版[ehang-io/nps](https://github.com/ehang-io/nps)（0.26）协议

- 组件配置全部实体化

  - 支持运行时修改&应用，无需重刷固件
  - 支持esphome原生触发器& action
  - 支持配置回滚防失联

## 2. 使用场景示例

#### 远程访问 ESP32 上的 Web 服务

场景：ESP32 内嵌一个 Web 服务（如 ESPHome web\_server 或其他 HTTP 服务），希望从公网随时访问，而不想在访问设备或访问设备所在局域网安装任何额外软件

服务器侧（nps Web 后台）：

- 新建 TCP 隧道：服务器端口 `8000`​，目标 `127.0.0.1:80`（客户端为 ESP32）

- 效果：公网访问 `http://服务器地址:8000` 即直达 ESP32 上的 Web 服务。

#### 远程 OTA 升级

场景：设备在非局域网的位置，需要从 PC 远程刷固件。

服务器侧：新建 TCP 隧道，服务器端口 `3232`​，目标 `127.0.0.1:3232`。

PC 侧：`esphome run xxxx.yaml --device 1.2.3.4(服务器公网ip）`

#### 远程日志调试

场景：查看 ESP32 运行日志

服务器侧：新建 TCP 隧道，服务器端口 `6053`​，目标 `127.0.0.1:6053`。

PC 侧：`esphome logs xxxx.yaml --device 1.2.3.4(服务器公网ip）`

#### 远程API接入

场景：在外地的epshome节点，接入家里的HA服务器

服务器侧：新建 TCP 隧道，服务器端口 `6053`​，目标 `127.0.0.1:6053`。

HA侧： 添加esphome设备，主机填入服务器地址，端口填写6053

## 3. 兼容性

#### 服务器版本

- `nps_client`​支持[djylb/nps](https://github.com/djylb/nps)的二次开发版本协议（0.34实测）

  - ⚠️桥接模式只支持TCP与TLS
  - ✅支持隧道加密
  - ✅支持隧道Proxy Protocol
  - ❌不支持隧道压缩
  - ⚠️服务器端开启`secure_mod`时esp32端需配置time组件同步SNTP 时间

- `nps_client_origin`​支持 [ehang-io/nps](https://github.com/ehang-io/nps)原版协议(0.26实测)

  - ⚠️桥接模式只支持TCP
  - ✅支持隧道加密
  - ❌不支持隧道压缩

#### 芯片与框架

- ESP32 全系（C3/S2/S3 等），框架 ESP-IDF
- S3 等支持 PSRAM 的芯片可使用PSRAM减轻内存压力

#### ESPHome

- 实测版本为2026.7.4，无版本硬性要求
- 使用默认esp-idf toolchain编译通过，低版本platformio编译自行测试

## 4. 性能

#### 代理网络吞吐量

- 实测：download（ESP32→PC）约 200KB/s，upload（PC→ESP32）约 400KB/s，。
- lwIP 默认 5760 字节窗口是当前主要限制（ESP-IDF 全局网络默认值，组件不擅自修改）。

#### 内存消耗

|场景|内部 RAM 增量|
| --------------------| ----------------------------------------------------------|
|无会话（TCP 模式）|基础值X|
|无会话（TLS 模式）|X + 30KB(TLS上下文消耗)|
|TCP不加密/每连接|X + 30KB(连接消耗)|
|TCP加密/每连接|X + 30KB(连接消耗) + 30KB(加密消耗)|
|TLS不加密/每连接|X + 30KB(TLS上下文消耗) + 30KB(连接消耗)|
|TLS加密/每连接|X + 30KB(TLS上下文消耗) + 30KB(连接消耗)+ 30KB(加密消耗)|
|使用PSRAM|TLS 上下文和加密全部进 PSRAM，每会话约消耗20KB|

#### 使用建议（`nps_client`）

- 对于没有PSRAM的设备,如c3，建议使用TCP模式，不开启加密，每条连接消耗30KB
- 对于具有PSRAM的设备，如s3 ,可以按需使用TLS模式，不开启加密，每条连接消耗20KB
- 不建议开启加密，TLS模式本身已存在加密功能，再开加密双重消耗，且没有收益，如不需要加密，直接TCP即可

## 5. 安全性与使用边界

- 通过nps代理的端口，将直接暴露到公网，务必设置好OTA密码、API密钥、WEB登录验证！！！！

- 本组件不做证书CA校验，nps 桥接 TLS 为自签证书设计，客户端不做 CA/指纹验证，请在可信网络使用
- Proxy Protocol 由服务器生成、后端消费：ESP32 仅透传；后端不支持解析时不要开启，否则协议会坏（HTTP 尤其明显）

## 6. 配置示列

#### 引入组件

```yaml
external_components:
  - source:
      type: git
      url: https://github.com/xxxxxxxx   #本仓库地址
      ref: main
    components:
      - nps_client
	  - nps_client_origin
    refresh: always
```

#### 配置示列

```yaml
nps_client:  #组件名，djylb/nps使用nps_client，原版ehang-io/nps使用nps_client_origin
  use_psram: true     #是否启用psram，需提前配置好pseram组件并确保可用
  connection_enabled:      #npc功能总开关，switch实体
    name: "NPC Enabled"
    entity_category: "config"
    restore_mode: RESTORE_DEFAULT_ON

  server_text:              #nps服务器地址，text实体
    name: "NPS Server"
    initial_value: "nps.xxxxx.cn"  #可选配置初始化地址，支持ip与域名，用于开箱即用场景
    entity_category: "config"

  tcp_port_text:            #nps服务器tcp桥接端口，text实体
    name: "NPS TCP Port"
    initial_value: "8024"     #可选配置初始化端口，用于开箱即用场景
    entity_category: "config"

  tls_port_text:           #nps服务器tls桥接端口，text实体，仅nps_client可使用，nps_client_origin不要配置
    name: "NPS TLS Port"
    initial_value: "8025"   #可选配置初始化端口，用于开箱即用场景
    entity_category: "config"

  mode_select:            #npc桥接模式，select实体，仅nps_client可使用，nps_client_origin不要配置
    name: "NPS Mode"
    initial_option: tls   #可选配置初始化模式tls/tcp，用于开箱即用场景
    entity_category: "config"

  client_vkey_text:        #npc连接密钥key，text实体
    name: "NPS Vkey"
    mode: PASSWORD
    initial_value: ${nps_client_key}  #可选配置初始化key，用于开箱即用场景
    entity_category: "config"

  legacy_version_text:       #nps服务器版本，select实体，可选配置，仅nps_client_origin可使用，不配置时组件会自动遍历匹配，建议不配置此实体
    name: "NPS Version"
    initial_value: "0.26.0"   #0.26.x 服务端为 "0.26.0"（默认值，无需配置），更老版本按对应服务端实际核心版本填写（如 0.25.x 为 "0.25.0"）
    entity_category: "config"

  config_apply_button:       #npc配置应用按钮， button实体
    name: "NPC Config Apply"
    entity_category: "config"

  config_rollback:             #npc坏配置回滚，switch实体
    name: "NPC Bad Config Rollback"
    entity_category: "config"
    restore_mode: RESTORE_DEFAULT_ON

  connection_status:         #npc连接状态，binary sensor实体
    name: "NPC Status"
    device_class: connectivity
    id: nps_connection_status
    entity_category: "diagnostic"

  connection_duration:   #npc连接时长，text sensor实体
    name: "NPC Connection Duration"
    id: nps_connection_duration
    entity_category: "diagnostic"
```

#### 配置补充

- switch、text、select等实体，支持esphome官方相关的Action动作和Condition判断
- binary sensor、text sensor支持esphome官方相关的on_xxxx触发器
- API配置，必须配置加密密钥！如需使用esphome cli logs ，将`api_port`设置与代理端口一致

  ```yaml
  api:
    reboot_timeout: 0s
    encryption:
      key: ${api_ota_key}
    port: ${api_port}
  ```
- OTA设置，必须配置密码！，如需使用 esphome cli run来ota，将`ota_port`设置与代理端口一致

  ```yaml
  ota:
    - platform: esphome
      password: ${ota_key}
      port: ${ota_port}
  ```
- Web设置，必须配置登录信息！，端口可保持默认（不显式配置即可）

  ```yaml
  web_server:
    auth:
      type: basic
      username: ${web_user}
      password: ${web_passwd}
  ```

-  HA、Web实体示列

   HA与Web的实体是一致的，此处演示HA界面  
   <img width="870" height="689" alt="image-20260820202733-nbja1b3" src="https://github.com/user-attachments/assets/36b899b4-22c7-4124-8430-70ffe01028e0" />

## 7 连接到NPS并设置代理隧道

#### 配置NPC参数并连接

- 如连接正常，nps服务器-客户端面板就会显示节点状态  
  <img width="1620" height="405" alt="image-20260820002735-urzgrk6" src="https://github.com/user-attachments/assets/c13703b6-da10-407e-806c-c1e711d7c354" />

- HA实体也会同步连接状态  
  <img width="418" height="188" alt="image-20260820002856-ykl8vic" src="https://github.com/user-attachments/assets/dd4b01d2-436c-450f-a3ef-c63064d5b64e" />

- 注意客户端配置，不要开启加密和压缩，如需加密，将桥接模式切换到TLS

#### 添加TCP隧道

服务端端口按你实际来，目标 (IP:端口)一般可设置下面几个

- api端口：127.0.0.1:6053，用于HA接入和日志调试
- OTA端口：127.0.0.1:3232, 用于远程OTA
- Web端口： 127.0.0.1:80，用于远程访问web，注意公有云没备案，只能用ip+端口或https域名+端口访问，不能http域名+端口访问
	<img width="1596" height="336" alt="image-20260820003513-cpcng0x" src="https://github.com/user-attachments/assets/37f68d90-c498-4690-9a61-f966d28eb2d1" />

#### 将外网esphome设备接入HA

1. 进入HA的esphome集成，右上添加设备
2. 按提示填写主机地址和端口，主机地址可以是nps服务器公网ip和域名，端口是nps对应的转发端口
3. 点击提交，会让你输入固件预设的api密钥  
  <img width="557" height="374" alt="image-20260820003856-fbstw8w" src="https://github.com/user-attachments/assets/ea332f58-d738-48b7-8c39-f86e6c3f4646" />

