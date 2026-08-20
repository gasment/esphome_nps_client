import esphome.codegen as cg
import esphome.config_validation as cv
import esphome.final_validate as fv
from esphome.components import (
    binary_sensor,
    button,
    select,
    switch,
    text,
    text_sensor,
)
from esphome.const import (
    CONF_ID,
    CONF_INITIAL_OPTION,
    CONF_INITIAL_VALUE,
    CONF_MAX_LENGTH,
    CONF_MIN_LENGTH,
    CONF_PATTERN,
    PLATFORM_ESP32,
)

DEPENDENCIES = [PLATFORM_ESP32]
AUTO_LOAD = [
    "network",
    "binary_sensor",
    "text_sensor",
    "text",
    "select",
    "button",
    "switch",
]

nps_ns = cg.esphome_ns.namespace("nps")
NpsComponent = nps_ns.class_("NpsComponent", cg.Component)
NpsConfigText = nps_ns.class_("NpsConfigText", text.Text)
NpsConfigSelect = nps_ns.class_("NpsConfigSelect", select.Select)
NpsConfigApplyButton = nps_ns.class_("NpsConfigApplyButton", button.Button)
NpsConfigSwitch = nps_ns.class_(
    "NpsConfigSwitch", switch.Switch, cg.Component
)

CONF_SERVER = "server"
CONF_MODE = "mode"
CONF_TCP_PORT = "tcp_port"
CONF_TLS_PORT = "tls_port"
CONF_VKEY = "client_vkey"
CONF_LOCAL_IP = "local_ip"
CONF_PROTO_VERSION = "proto_version"
CONF_CONNECT_TIMEOUT_S = "connect_timeout_s"
CONF_RECONNECT_DELAY_S = "reconnect_delay_s"
CONF_DISCONNECT_TIMEOUT_S = "disconnect_timeout_s"
CONF_USE_PSRAM = "use_psram"
CONF_TASK_STACK = "task_stack"
CONF_CONNECTION_STATUS = "connection_status"
CONF_CONNECTION_DURATION = "connection_duration"

# 运行时预配置实体
CONF_SERVER_TEXT = "server_text"
CONF_TCP_PORT_TEXT = "tcp_port_text"
CONF_TLS_PORT_TEXT = "tls_port_text"
CONF_VKEY_TEXT = "client_vkey_text"
CONF_MODE_SELECT = "mode_select"
CONF_APPLY_BUTTON = "config_apply_button"
CONF_CONFIG_ROLLBACK = "config_rollback"
CONF_CONNECTION_ENABLED = "connection_enabled"


def _runtime_text_schema(
    default_max_length: int, *, pattern: str | None = None
) -> cv.Schema:
    """可编辑文本实体：修改即写入 slotB 预配置。"""
    schema = {
        cv.Optional(CONF_MIN_LENGTH, default=1): cv.int_range(min=0, max=255),
        cv.Optional(
            CONF_MAX_LENGTH, default=default_max_length
        ): cv.int_range(min=0, max=255),
        cv.Optional(CONF_INITIAL_VALUE): cv.string_strict,
    }
    if pattern is not None:
        schema[cv.Optional(CONF_PATTERN)] = cv.string
    return text.text_schema(NpsConfigText, mode="TEXT").extend(schema)


_MODE_SELECT_SCHEMA = select.select_schema(NpsConfigSelect).extend(
    {
        cv.Optional(CONF_INITIAL_OPTION): cv.one_of(
            "tcp", "tls", lower=True
        ),
    }
)


def _final_validate_psram(config: dict) -> dict:
    if config.get(CONF_USE_PSRAM, False):
        full_config = fv.full_config.get()
        if full_config.get("psram") is None:
            raise cv.Invalid(
                "nps_client: 'use_psram: true' requires the 'psram:' component to be "
                "enabled in the configuration"
            )
    return config


def _validate_server(config: dict) -> dict:
    server = config.get(CONF_SERVER, "")
    if server and ":" in server:
        raise cv.Invalid(
            "nps_client: 'server' 只填 IP 或域名，端口请用 'tcp_port' / 'tls_port' 配置"
        )
    return config


def _validate_config_sources(config: dict) -> dict:
    """server / client_vkey 可来自静态配置或运行时实体（至少其一）。"""
    if not config.get(CONF_SERVER) and CONF_SERVER_TEXT not in config:
        raise cv.Invalid(
            "nps_client: 请提供 'server' 或 'server_text'（initial_value 或运行时可编辑）"
            "作为服务器来源"
        )
    if not config.get(CONF_VKEY) and CONF_VKEY_TEXT not in config:
        raise cv.Invalid(
            "nps_client: 请提供 'client_vkey' 或 'client_vkey_text' 作为验证密钥来源"
        )
    return config


def _final_validate_mbedtls(config: dict) -> dict:
    full_config = fv.full_config.get()
    esp32 = full_config.get("esp32") or {}
    framework = esp32.get("framework") or {}
    opts = framework.get("sdkconfig_options") or {}
    value = opts.get("CONFIG_MBEDTLS_DYNAMIC_BUFFER")
    if value in (True, "y", "Y", 1, "1"):
        raise cv.Invalid(
            "nps_client: 'CONFIG_MBEDTLS_DYNAMIC_BUFFER' 与本组件不兼容"
            "（TLS 1.3 长连接下会堆损坏崩溃），"
            "请从 'esp32.framework.sdkconfig_options' 中移除该选项"
        )
    return config


CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(NpsComponent),
            cv.Optional(CONF_SERVER, default=""): cv.string,
            cv.Optional(CONF_MODE, default="tcp"): cv.one_of(
                "tcp", "tls", lower=True
            ),
            cv.Optional(CONF_TCP_PORT, default=8024): cv.port,
            cv.Optional(CONF_TLS_PORT, default=8025): cv.port,
            cv.Optional(CONF_VKEY, default=""): cv.string_strict,
            cv.Optional(CONF_LOCAL_IP, default=""): cv.string,
            cv.Optional(CONF_PROTO_VERSION, default=9): cv.int_range(
                min=5, max=9
            ),
            cv.Optional(CONF_CONNECT_TIMEOUT_S, default=10): cv.int_range(
                min=3, max=60
            ),
            cv.Optional(CONF_RECONNECT_DELAY_S, default=5): cv.int_range(
                min=1, max=300
            ),
            cv.Optional(CONF_DISCONNECT_TIMEOUT_S, default=60): cv.int_range(
                min=5, max=600
            ),
            cv.Optional(CONF_USE_PSRAM, default=False): cv.boolean,
            cv.Optional(CONF_TASK_STACK, default=14336): cv.int_range(
                min=8192, max=65536
            ),
            cv.Optional(CONF_CONNECTION_STATUS): binary_sensor.binary_sensor_schema(),
            cv.Optional(CONF_CONNECTION_DURATION): text_sensor.text_sensor_schema(),
            cv.Optional(CONF_SERVER_TEXT): _runtime_text_schema(159),
            cv.Optional(CONF_TCP_PORT_TEXT): _runtime_text_schema(
                5, pattern="[0-9]{1,5}"
            ),
            cv.Optional(CONF_TLS_PORT_TEXT): _runtime_text_schema(
                5, pattern="[0-9]{1,5}"
            ),
            cv.Optional(CONF_VKEY_TEXT): _runtime_text_schema(127),
            cv.Optional(CONF_MODE_SELECT): _MODE_SELECT_SCHEMA,
            cv.Optional(CONF_APPLY_BUTTON): button.button_schema(
                NpsConfigApplyButton
            ),
            cv.Optional(CONF_CONFIG_ROLLBACK): switch.switch_schema(
                NpsConfigSwitch,
                block_inverted=True,
                default_restore_mode="RESTORE_DEFAULT_ON",
            ),
            cv.Optional(CONF_CONNECTION_ENABLED): switch.switch_schema(
                NpsConfigSwitch,
                block_inverted=True,
                default_restore_mode="RESTORE_DEFAULT_ON",
            ),
        }
    ),
    _validate_server,
    _validate_config_sources,
    cv.only_on([PLATFORM_ESP32]),
    cv.only_with_framework(["esp-idf"]),
)

FINAL_VALIDATE_SCHEMA = cv.All(_final_validate_psram, _final_validate_mbedtls)


async def _create_runtime_text(var, config, key):
    if key not in config:
        return
    ent_cfg = config[key]
    ent = await text.new_text(
        ent_cfg,
        min_length=ent_cfg[CONF_MIN_LENGTH],
        max_length=ent_cfg[CONF_MAX_LENGTH],
        pattern=ent_cfg.get(CONF_PATTERN),
    )
    setter = {
        CONF_SERVER_TEXT: "set_server_text",
        CONF_TCP_PORT_TEXT: "set_tcp_port_text",
        CONF_TLS_PORT_TEXT: "set_tls_port_text",
        CONF_VKEY_TEXT: "set_vkey_text",
    }[key]
    initial = {
        CONF_SERVER_TEXT: "set_initial_server",
        CONF_TCP_PORT_TEXT: "set_initial_tcp_port",
        CONF_TLS_PORT_TEXT: "set_initial_tls_port",
        CONF_VKEY_TEXT: "set_initial_vkey",
    }[key]
    cg.add(getattr(var, setter)(ent))
    if CONF_INITIAL_VALUE in ent_cfg:
        cg.add(getattr(var, initial)(ent_cfg[CONF_INITIAL_VALUE]))


async def to_code(config):
    # Go 服务端（djylb/nps）可能协商 TLS 1.3；保持对端证书以支持 RSA-PSS 套件。
    from esphome.components.esp32 import add_idf_sdkconfig_option

    if config[CONF_USE_PSRAM]:
        # mbedTLS 全部走外部 SPIRAM（bridge TLS + 隧道级 TLS 上下文），
        # 把每会话约 30KB 的 TLS 开销从内部 RAM 挪到 PSRAM。
        # 依赖 psram 组件开启的 CONFIG_SPIRAM_USE_CAPS_ALLOC。
        add_idf_sdkconfig_option("CONFIG_MBEDTLS_EXTERNAL_MEM_ALLOC", True)
    add_idf_sdkconfig_option("CONFIG_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE", True)
    add_idf_sdkconfig_option("CONFIG_MBEDTLS_SSL_PROTO_TLS1_3", True)
    add_idf_sdkconfig_option("CONFIG_MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE", True)
    add_idf_sdkconfig_option("CONFIG_MBEDTLS_SSL_TLS1_3_KEXM_EPHEMERAL", True)
    add_idf_sdkconfig_option("CONFIG_MBEDTLS_KEY_EXCHANGE_ELLIPTIC_CURVE", True)
    add_idf_sdkconfig_option("CONFIG_MBEDTLS_KEY_EXCHANGE_ECDHE_RSA", True)

    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    cg.add(var.set_server(config[CONF_SERVER]))
    cg.add(var.set_mode(config[CONF_MODE]))
    cg.add(var.set_tcp_port(config[CONF_TCP_PORT]))
    cg.add(var.set_tls_port(config[CONF_TLS_PORT]))
    cg.add(var.set_vkey(config[CONF_VKEY]))
    cg.add(var.set_local_ip(config[CONF_LOCAL_IP]))
    cg.add(var.set_proto_version(config[CONF_PROTO_VERSION]))
    cg.add(var.set_connect_timeout_s(config[CONF_CONNECT_TIMEOUT_S]))
    cg.add(var.set_reconnect_delay_s(config[CONF_RECONNECT_DELAY_S]))
    cg.add(var.set_disconnect_timeout_s(config[CONF_DISCONNECT_TIMEOUT_S]))
    cg.add(var.set_use_psram(config[CONF_USE_PSRAM]))
    cg.add(var.set_task_stack(config[CONF_TASK_STACK]))
    if CONF_CONNECTION_STATUS in config:
        sens = await binary_sensor.new_binary_sensor(config[CONF_CONNECTION_STATUS])
        cg.add(var.set_connection_status(sens))
    if CONF_CONNECTION_DURATION in config:
        sens = await text_sensor.new_text_sensor(config[CONF_CONNECTION_DURATION])
        cg.add(var.set_connection_duration(sens))

    for key in (
        CONF_SERVER_TEXT,
        CONF_TCP_PORT_TEXT,
        CONF_TLS_PORT_TEXT,
        CONF_VKEY_TEXT,
    ):
        await _create_runtime_text(var, config, key)

    if CONF_MODE_SELECT in config:
        ent_cfg = config[CONF_MODE_SELECT]
        ent = await select.new_select(ent_cfg, options=["tcp", "tls"])
        cg.add(var.set_mode_select(ent))
        if CONF_INITIAL_OPTION in ent_cfg:
            cg.add(var.set_initial_mode(ent_cfg[CONF_INITIAL_OPTION]))

    if CONF_APPLY_BUTTON in config:
        await button.new_button(config[CONF_APPLY_BUTTON], var)

    if CONF_CONFIG_ROLLBACK in config:
        sw = await switch.new_switch(config[CONF_CONFIG_ROLLBACK], var)
        cg.add(var.set_config_rollback_switch(sw))
        await cg.register_component(sw, config[CONF_CONFIG_ROLLBACK])

    if CONF_CONNECTION_ENABLED in config:
        sw = await switch.new_switch(config[CONF_CONNECTION_ENABLED], var)
        cg.add(var.set_connection_enabled_switch(sw))
        await cg.register_component(sw, config[CONF_CONNECTION_ENABLED])
