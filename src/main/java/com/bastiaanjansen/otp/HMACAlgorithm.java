package com.bastiaanjansen.otp;

/**
 * HMAC algorithm enum
 * @author Bastiaan Jansen
 */
public enum HMACAlgorithm {

    @Deprecated
    SHA1("HmacSHA1", 160),
    SHA224("HmacSHA224", 224),
    SHA256("HmacSHA256", 256),
    SHA384("HmacSHA384", 384),
    SHA512("HmacSHA512", 512);

    private final String name;

    private final int recommendedKeyBits;

    HMACAlgorithm(String name, int recommendedKeyBits) {
        this.name = name;
        this.recommendedKeyBits = recommendedKeyBits;
    }

    public String getHMACName() {
        return name;
    }

    /**
     * Recommended secret size in bits for this algorithm, equal to the HMAC output size as recommended by
     * RFC 4226 section 4. The enforced minimum for all algorithms is {@link OTPValidator#MIN_SECRET_BITS}.
     *
     * @return recommended secret size in bits
     */
    public int getRecommendedKeyBits() {
        return recommendedKeyBits;
    }
}
