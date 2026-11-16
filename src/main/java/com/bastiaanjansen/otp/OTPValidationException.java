package com.bastiaanjansen.otp;

/**
 * Base exception for all OTP policy violations, thrown when a secret, password length or algorithm does not
 * meet the boundaries enforced by {@link OTPValidator}.
 * <p>
 * It extends {@link IllegalArgumentException} so existing callers keep working, while new callers can catch
 * this type (or one of its subclasses) to classify validation errors.
 */
public class OTPValidationException extends IllegalArgumentException {

    public OTPValidationException(final String message) {
        super(message);
    }

    public OTPValidationException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
