package com.bastiaanjansen.otp;

/**
 * Thrown when a secret is empty, not decodable or does not provide the minimum required entropy.
 */
public class InvalidSecretException extends OTPValidationException {

    public InvalidSecretException(final String message) {
        super(message);
    }
}
