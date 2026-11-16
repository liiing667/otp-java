package com.bastiaanjansen.otp;

/**
 * Thrown when a password length (digits) falls outside the supported boundaries.
 */
public class InvalidPasswordLengthException extends OTPValidationException {

    public InvalidPasswordLengthException(final String message) {
        super(message);
    }
}
