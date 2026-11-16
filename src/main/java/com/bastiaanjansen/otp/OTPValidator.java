package com.bastiaanjansen.otp;

import org.apache.commons.codec.binary.Base32;

/**
 * Shared security boundaries for one-time password configuration. The same limits are enforced when
 * generating secrets ({@link SecretGenerator}), importing OTPAuth URIs
 * ({@link HOTPGenerator#fromURI(java.net.URI)}, {@link TOTPGenerator#fromURI(java.net.URI)}) and building
 * generators ({@link HOTPGenerator.Builder}, {@link TOTPGenerator.Builder}), so a configuration is either
 * accepted everywhere or rejected everywhere, and rejected eagerly instead of at code-generation time.
 */
public final class OTPValidator {

    /**
     * Minimum number of digits of a generated one-time password
     */
    public static final int MIN_PASSWORD_LENGTH = 6;

    /**
     * Maximum number of digits of a generated one-time password
     */
    public static final int MAX_PASSWORD_LENGTH = 8;

    /**
     * Minimum secret entropy in bits. RFC 4226 section 4 requires keys of at least 128 bits.
     */
    public static final int MIN_SECRET_BITS = 128;

    private static final Base32 base32 = new Base32();

    private OTPValidator() {}

    /**
     * Validates a password length (digits).
     *
     * @param passwordLength number of digits of the generated one-time password
     * @throws InvalidPasswordLengthException when the length is outside the supported boundaries
     */
    public static void validatePasswordLength(final int passwordLength) throws InvalidPasswordLengthException {
        if (passwordLength < MIN_PASSWORD_LENGTH || passwordLength > MAX_PASSWORD_LENGTH)
            throw new InvalidPasswordLengthException(
                    String.format("Password length must be between %d and %d digits", MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH)
            );
    }

    /**
     * Validates a requested secret size in bits.
     *
     * @param bits requested secret entropy in bits
     * @throws InvalidSecretException when the requested size provides less than the minimum required entropy
     */
    public static void validateSecretBits(final int bits) throws InvalidSecretException {
        if (bits < MIN_SECRET_BITS)
            throw new InvalidSecretException(
                    String.format("Secret must be at least %d bits, %d bits requested", MIN_SECRET_BITS, bits)
            );
    }

    /**
     * Validates a Base32 encoded secret.
     *
     * @param secret Base32 encoded secret
     * @throws InvalidSecretException when the secret is empty or provides less than the minimum required entropy
     */
    public static void validateSecret(final byte[] secret) throws InvalidSecretException {
        if (secret == null || secret.length == 0)
            throw new InvalidSecretException("Secret must not be empty");

        byte[] decoded = base32.decode(secret);
        if (decoded.length * Byte.SIZE < MIN_SECRET_BITS)
            throw new InvalidSecretException(
                    String.format("Secret must contain at least %d bits of entropy, %d bits provided", MIN_SECRET_BITS, decoded.length * Byte.SIZE)
            );
    }
}
