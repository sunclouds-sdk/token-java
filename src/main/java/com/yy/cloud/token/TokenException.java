package com.yy.cloud.token;

public class TokenException extends RuntimeException {

    public TokenException() {
        super();
    }

    public TokenException(String message) {
        super(message);
    }

    public TokenException(String message, Throwable e) {
        super(message, e);
    }

    public TokenException(Throwable e) {
        super(e);
    }

}
