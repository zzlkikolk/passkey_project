package com.example.passkey.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Minimal CBOR reader for the definite-length maps used by WebAuthn COSE keys. */
public final class CborReader {
    private final ByteArrayInputStream input;
    /** 创建一个读取指定 CBOR 二进制数据的解析器。 */
    public CborReader(byte[] data) { this.input = new ByteArrayInputStream(data); }

    /** 读取一个 CBOR 值，返回 Java 基础类型、列表或 Map。 */
    public Object read() throws IOException {
        int initial = input.read();
        if (initial < 0) throw new IOException("Unexpected end of CBOR");
        int major = initial >>> 5; // 高三位表示 CBOR 主类型。
        long additional = readLength(initial & 31);
        if (major == 0) return additional;
        if (major == 1) return -1L - additional;
        if (major == 2) return readBytes(checkedLength(additional)); // byte string，用于公钥坐标和 authData。
        if (major == 3) return new String(readBytes(checkedLength(additional)), StandardCharsets.UTF_8);
        if (major == 4) {
            List<Object> list = new ArrayList<>();
            for (long i = 0; i < additional; i++) list.add(read());
            return list;
        }
        if (major == 5) { // COSE 公钥本身就是一个整数键 Map。
            Map<Object, Object> map = new LinkedHashMap<>();
            for (long i = 0; i < additional; i++) map.put(read(), read());
            return map;
        }
        if (major == 7) {
            if (additional == 20) return Boolean.FALSE;
            if (additional == 21) return Boolean.TRUE;
            if (additional == 22) return null;
        }
        throw new IOException("Unsupported CBOR value");
    }

    /** 读取 CBOR 的附加长度字段。 */
    private long readLength(int additional) throws IOException {
        if (additional < 24) return additional;
        if (additional == 24) return input.read();
        if (additional == 25) return (input.read() << 8) | input.read();
        if (additional == 26) return ((long) input.read() << 24) | ((long) input.read() << 16)
                | ((long) input.read() << 8) | input.read();
        if (additional == 27) {
            long result = 0;
            for (int i = 0; i < 8; i++) result = (result << 8) | input.read();
            return result;
        }
        throw new IOException("Indefinite CBOR values are unsupported");
    }

    /** 从输入流读取指定长度的二进制值。 */
    private byte[] readBytes(int length) throws IOException {
        byte[] value = input.readNBytes(length);
        if (value.length != length) throw new IOException("Unexpected end of CBOR bytes");
        return value;
    }

    /** 将 CBOR 长度安全转换为 Java 数组长度。 */
    private int checkedLength(long length) throws IOException {
        if (length < 0 || length > Integer.MAX_VALUE) throw new IOException("CBOR value too large");
        return (int) length;
    }
}
