package com.bastiaanjansen.otp;

import org.apache.commons.codec.binary.Base32;

import java.security.SecureRandom;

/**
 * A secret generator to generate OTP secrets
 *
 * @author Bastiaan Jansen
 */
public class SecretGenerator {

    private SecretGenerator() {}

    /**
     * Default amount of bits for secret generation
     */
    public static final int DEFAULT_BITS = 160;

    private static final SecureRandom random = new SecureRandom();
    private static final Base32 encoder = new Base32();

    /**
     * Generate an OTP base32 secret with default amount of bits
     *
     * @return generated secret
     */
    public static byte[] generate() {
        return generate(DEFAULT_BITS);
    }

    /**
     * Generate an OTP base32 secret with the recommended amount of bits for the given HMAC algorithm
     *
     * @param algorithm HMAC algorithm the secret will be used with
     * @return generated secret
     */
    public static byte[] generate(final HMACAlgorithm algorithm) {
        return generate(algorithm.getRecommendedKeyBits());
    }

    /**
     * Generate an OTP base32 secret
     *
     * @param bits length, must be at least {@link OTPValidator#MIN_SECRET_BITS} bits. It is recommended to
     *             use at least the length of the HMAC algorithm type:
     *             SHA1: 160 bits
     *             SHA256: 256 bits
     *             SHA512: 512 bits
     * @return generated secret
     * @throws InvalidSecretException when the requested amount of bits is below the minimum
     */
    public static byte[] generate(final int bits) throws InvalidSecretException {
        OTPValidator.validateSecretBits(bits);

        // Round up to whole bytes so the requested entropy is never truncated
        byte[] bytes = new byte[(bits + Byte.SIZE - 1) / Byte.SIZE];
        random.nextBytes(bytes);

        // Encode full random bytes instead of sampling characters from the Base32 alphabet one by one,
        // so no entropy is lost to modulo bias of the random source
        return encoder.encode(bytes);
    }
}
