import esphome.codegen as cg
import esphome.config_validation as cv
import esphome.final_validate as fv
from esphome.components import (
    binary_sensor,
    button,
    switch,
    text,
    text_sensor,
)
from esphome.const import (
    CONF_ID,
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
    "button",
    "switch",
]

nps_origin_ns = cg.esphome_ns.namespace("nps_origin")
NpsComponent = nps_origin_ns.class_("NpsComponent", cg.Component)
NpsConfigText = nps_origin_ns.class_("NpsConfigText", text.Text)
NpsConfigApplyButton = nps_origin_ns.class_("NpsConfigApplyButton", button.Button)
NpsConfigSwitch = nps_origin_ns.class_(
    "NpsConfigSwitch", switch.Switch, cg.Component
)

CONF_SERVER = "server"
CONF_TCP_PORT = "tcp_port"
CONF_VKEY = "client_vkey"
CONF_LEGACY_VERSION = "legacy_version"
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
CONF_VKEY_TEXT = "client_vkey_text"
CONF_LEGACY_VERSION_TEXT = "legacy_version_text"
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


def _final_validate_psram(config: dict) -> dict:
    if config.get(CONF_USE_PSRAM, False):
        full_config = fv.full_config.get()
        if full_config.get("psram") is None:
            raise cv.Invalid(
                "nps_client_origin: 'use_psram: true' requires the 'psram:' "
                "component to be enabled in the configuration"
            )
    return config


def _validate_server(config: dict) -> dict:
    server = config.get(CONF_SERVER, "")
    if server and ":" in server:
        raise cv.Invalid(
            "nps_client_origin: 'server' 只填 IP 或域名，端口请用 'tcp_port' 配置"
        )
    return config


def _validate_config_sources(config: dict) -> dict:
    """server / client_vkey 可来自静态配置或运行时实体（至少其一）。"""
    if not config.get(CONF_SERVER) and CONF_SERVER_TEXT not in config:
        raise cv.Invalid(
            "nps_client_origin: 请提供 'server' 或 'server_text'（initial_value 或"
            "运行时可编辑）作为服务器来源"
        )
    if not config.get(CONF_VKEY) and CONF_VKEY_TEXT not in config:
        raise cv.Invalid(
            "nps_client_origin: 请提供 'client_vkey' 或 'client_vkey_text' 作为验证密钥来源"
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
            "nps_client_origin: 'CONFIG_MBEDTLS_DYNAMIC_BUFFER' 与本组件不兼容"
            "（TLS 长连接下会堆损坏崩溃），请从 "
            "'esp32.framework.sdkconfig_options' 中移除该选项"
        )
    return config


CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(NpsComponent),
            cv.Optional(CONF_SERVER, default=""): cv.string,
            cv.Optional(CONF_TCP_PORT, default=8024): cv.port,
            cv.Optional(CONF_VKEY, default=""): cv.string_strict,
            cv.Optional(CONF_LEGACY_VERSION, default="0.26.0"): cv.All(
                cv.string, cv.Length(min=1, max=15)
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
            cv.Optional(CONF_VKEY_TEXT): _runtime_text_schema(127),
            cv.Optional(CONF_LEGACY_VERSION_TEXT): _runtime_text_schema(15),
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
        CONF_VKEY_TEXT: "set_vkey_text",
        CONF_LEGACY_VERSION_TEXT: "set_legacy_version_text",
    }[key]
    initial = {
        CONF_SERVER_TEXT: "set_initial_server",
        CONF_TCP_PORT_TEXT: "set_initial_tcp_port",
        CONF_VKEY_TEXT: "set_initial_vkey",
        CONF_LEGACY_VERSION_TEXT: "set_initial_legacy_version",
    }[key]
    cg.add(getattr(var, setter)(ent))
    if CONF_INITIAL_VALUE in ent_cfg:
        cg.add(getattr(var, initial)(ent_cfg[CONF_INITIAL_VALUE]))


async def to_code(config):
    from esphome.components.esp32 import add_idf_sdkconfig_option
    from esphome.components import esp32

    # ESPHome 2026.10+ removes TLS unless a consumer explicitly requests it.
    # Older releases keep TLS enabled and do not provide this helper.
    if hasattr(esp32, "require_mbedtls_tls"):
        esp32.require_mbedtls_tls()

    if config[CONF_USE_PSRAM]:
        # Only the TLS allocation policy depends on PSRAM availability.
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
    cg.add(var.set_tcp_port(config[CONF_TCP_PORT]))
    cg.add(var.set_vkey(config[CONF_VKEY]))
    cg.add(var.set_legacy_version(config[CONF_LEGACY_VERSION]))
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
        CONF_VKEY_TEXT,
        CONF_LEGACY_VERSION_TEXT,
    ):
        await _create_runtime_text(var, config, key)

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
