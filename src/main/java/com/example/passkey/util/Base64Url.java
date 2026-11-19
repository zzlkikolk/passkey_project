package com.example.passkey.util;

import java.util.Base64;

/** WebAuthn 常用的无填充 Base64URL 编解码工具。 */
public final class Base64Url {
    /** 工具类不允许实例化。 */
    private Base64Url() { }
    /** 将二进制数据编码为 Base64URL 字符串。 */
    public static String encode(byte[] value) { return Base64.getUrlEncoder().withoutPadding().encodeToString(value); }
    /** 将 Base64URL 字符串解码为二进制数据。 */
    public static byte[] decode(String value) { return Base64.getUrlDecoder().decode(value); }
}
