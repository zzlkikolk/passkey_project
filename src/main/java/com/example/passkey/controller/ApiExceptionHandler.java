package com.example.passkey.controller;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Collections;
import java.util.Map;

@RestControllerAdvice
/** 将业务参数错误统一转换成 HTTP 400 JSON 响应。 */
public class ApiExceptionHandler {
    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    /** 返回前端可直接展示的错误消息。 */
    public Map<String, Object> badRequest(IllegalArgumentException exception) {
        return Collections.unmodifiableMap(new java.util.LinkedHashMap<String, Object>() {{
            put("error", exception.getMessage());
        }});
    }
}
