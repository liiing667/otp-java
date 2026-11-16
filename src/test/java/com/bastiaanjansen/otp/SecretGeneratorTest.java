package com.bastiaanjansen.otp;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SecretGeneratorTest {

    @Test
    void generate_defaultLengthIs32() {
        int expected = 32;
        assertThat(SecretGenerator.generate().length, is(expected));
    }

    @Test
    void generate_lengthIs56() {
        int expected = 56;
        assertThat(SecretGenerator.generate(256).length, is(expected));
    }

    @Test
    void generateWithZeroBits_throwsIllegalArgument() {
        assertThrows(IllegalArgumentException.class, () -> SecretGenerator.generate(0));
    }

    @Test
    void generateWithLessThanZeroBits_throwsIllegalArgument() {
        assertThrows(IllegalArgumentException.class, () -> SecretGenerator.generate(-1));
    }

    @Test
    void generateWithLessThanMinimumBits_throwsInvalidSecret() {
        assertThrows(InvalidSecretException.class, () -> SecretGenerator.generate(64));
    }

    @Test
    void generateWithMinimumBits_lengthIs32() {
        int expected = 32;
        assertThat(SecretGenerator.generate(OTPValidator.MIN_SECRET_BITS).length, is(expected));
    }

    @Test
    void generateWithBitsNotDivisibleByEight_doesNotLoseEntropy() {
        // 129 bits must be rounded up to 17 bytes = 136 bits of entropy, never truncated to 128
        int expected = 32;
        assertThat(SecretGenerator.generate(129).length, is(expected));
    }

    @Test
    void generateWithAlgorithm_usesRecommendedKeyBits() {
        assertThat(SecretGenerator.generate(HMACAlgorithm.SHA1).length, is(32));
        assertThat(SecretGenerator.generate(HMACAlgorithm.SHA256).length, is(56));
        assertThat(SecretGenerator.generate(HMACAlgorithm.SHA512).length, is(104));
    }
}
