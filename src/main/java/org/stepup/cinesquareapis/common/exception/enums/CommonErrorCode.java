package org.stepup.cinesquareapis.common.exception.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum CommonErrorCode implements ErrorCode {
    INVALID_PARAMETER(HttpStatus.BAD_REQUEST, HttpStatus.BAD_REQUEST.value(), "Invalid parameter included"), // 저장할 파라미터 오류
    BAD_REQUEST(HttpStatus.BAD_REQUEST, HttpStatus.BAD_REQUEST.value(), "Invalid request"), // 저장할 파라미터 외 요청 오류
    UNAUTHORIZED(HttpStatus.UNAUTHORIZED, HttpStatus.UNAUTHORIZED.value(), "Unauthorized"),
    UNAUTHORIZED_ACTION(HttpStatus.FORBIDDEN,  HttpStatus.FORBIDDEN.value(), "You are not authorized to perform this action"),
    RESOURCE_NOT_FOUND(HttpStatus.NOT_FOUND, HttpStatus.BAD_REQUEST.value(),"Resource not exists"),
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, HttpStatus.INTERNAL_SERVER_ERROR.value(), "Internal server error")
    ;

    private final HttpStatus httpStatus;
    private final int code;
    private final String message;
}

