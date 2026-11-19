# Passkey Demo

这是一个可直接启动的 Passkey/WebAuthn 示例，后端使用 Java 11 + Spring Boot 2.3，前端是无需构建工具的原生 HTML/CSS/JavaScript。浏览器负责产生和保护私钥，服务端只保存凭据 ID、公钥和签名计数器。

## 启动前

1. 执行 `src/main/resources/db/schema.sql` 创建 MySQL 库表。
2. 启动本机 Redis，默认地址为 `127.0.0.1:6379`。
3. 如 MySQL 账号不是 `root/root`，通过 `DB_USERNAME`、`DB_PASSWORD` 或 `DB_URL` 覆盖配置。

## 启动

```bash
/Users/zhangzhilin/App/apache-maven-3.9.0/bin/mvn spring-boot:run
```

打开 <http://localhost:8080>，输入用户名和显示名称后点击“注册 Passkey”，然后点击“使用 Passkey 登录”。需要在安全上下文中使用 WebAuthn，`localhost` 开发地址已满足浏览器要求。

## API

- `POST /api/auth/register/options` 创建注册挑战。
- `POST /api/auth/register/verify` 校验注册响应并保存公钥。
- `POST /api/auth/login/options` 创建登录挑战。
- `POST /api/auth/login/verify` 校验签名和签名计数器。
- `GET /api/health` 健康检查。

挑战值保存在 Redis 并设置过期时间，用户和凭据保存在 MySQL。若环境无法直接创建数据库，先执行项目内的 SQL 即可。
