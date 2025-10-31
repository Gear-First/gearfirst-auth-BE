package com.gearfirst.backend.common.response;

public class ErrorResponse {
    private final Exception ex;
    public ErrorResponse(Exception ex) { this.ex = ex; }
    public String getMessage() { return ex.getMessage(); }
    public Exception getEx() {
        return ex;
    }
}
