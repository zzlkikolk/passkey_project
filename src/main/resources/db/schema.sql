-- Passkey 演示数据库。utf8mb4 用于兼容中文显示名称和用户名。
CREATE DATABASE IF NOT EXISTS passkey_demo DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE passkey_demo;

-- 应用用户表。一个用户可以绑定多个设备上的 Passkey。
CREATE TABLE IF NOT EXISTS passkey_user (
    id BIGINT PRIMARY KEY AUTO_INCREMENT COMMENT '数据库内部用户主键',
    username VARCHAR(128) NOT NULL UNIQUE COMMENT '登录用户名，业务上唯一',
    display_name VARCHAR(128) NOT NULL COMMENT '用户在注册时填写的显示名称',
    user_handle VARCHAR(64) NOT NULL UNIQUE COMMENT 'WebAuthn user.id，使用 Base64URL 编码保存',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '用户创建时间'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Passkey 凭据表。只保存凭据 ID、公钥和签名计数器，私钥始终留在用户设备中。
CREATE TABLE IF NOT EXISTS passkey_credential (
    id BIGINT PRIMARY KEY AUTO_INCREMENT COMMENT '数据库内部凭据主键',
    user_id BIGINT NOT NULL COMMENT '所属应用用户 ID',
    credential_id VARCHAR(512) NOT NULL UNIQUE COMMENT 'WebAuthn credential.rawId，使用 Base64URL 编码保存',
    public_key_x VARCHAR(128) NOT NULL COMMENT 'ES256 公钥椭圆曲线 X 坐标，使用 Base64URL 编码保存',
    public_key_y VARCHAR(128) NOT NULL COMMENT 'ES256 公钥椭圆曲线 Y 坐标，使用 Base64URL 编码保存',
    sign_count BIGINT NOT NULL DEFAULT 0 COMMENT '认证器返回的签名计数器，用于检测凭据克隆',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Passkey 创建时间',
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '凭据最后更新时间',
    CONSTRAINT fk_credential_user FOREIGN KEY (user_id) REFERENCES passkey_user(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
