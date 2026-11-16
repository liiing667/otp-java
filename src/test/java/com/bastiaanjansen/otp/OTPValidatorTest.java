package com.bastiaanjansen.otp;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OTPValidatorTest {

    @ParameterizedTest
    @ValueSource(ints = {6, 7, 8})
    void validatePasswordLengthWithValidLength_doesNotThrow(int passwordLength) {
        assertDoesNotThrow(() -> OTPValidator.validatePasswordLength(passwordLength));
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 5, 9, 10})
    void validatePasswordLengthWithInvalidLength_throwsInvalidPasswordLengthException(int passwordLength) {
        assertThrows(InvalidPasswordLengthException.class, () -> OTPValidator.validatePasswordLength(passwordLength));
    }

    @Test
    void validateSecretBitsWithMinimumBits_doesNotThrow() {
        assertDoesNotThrow(() -> OTPValidator.validateSecretBits(OTPValidator.MIN_SECRET_BITS));
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 0, 1, 127})
    void validateSecretBitsBelowMinimum_throwsInvalidSecretException(int bits) {
        assertThrows(InvalidSecretException.class, () -> OTPValidator.validateSecretBits(bits));
    }

    @Test
    void validateSecretWithEmptySecret_throwsInvalidSecretException() {
        assertThrows(InvalidSecretException.class, () -> OTPValidator.validateSecret(new byte[]{}));
    }

    @Test
    void validateSecretWithTooLittleEntropy_throwsInvalidSecretException() {
        // 8 Base32 characters decode to 5 bytes = 40 bits
        assertThrows(InvalidSecretException.class, () -> OTPValidator.validateSecret("JBSWY3DP".getBytes()));
    }

    @Test
    void validateSecretWithSufficientEntropy_doesNotThrow() {
        // 26 Base32 characters decode to 16 bytes = 128 bits
        assertDoesNotThrow(() -> OTPValidator.validateSecret("JBSWY3DPEHPK3PXPJBSWY3DPEA".getBytes()));
    }

    @Test
    void validationExceptions_areClassifiableAsOTPValidationException() {
        OTPValidationException secretException = assertThrows(OTPValidationException.class, () -> OTPValidator.validateSecret(new byte[]{}));
        OTPValidationException lengthException = assertThrows(OTPValidationException.class, () -> OTPValidator.validatePasswordLength(5));

        assertThat(secretException, is(instanceOf(InvalidSecretException.class)));
        assertThat(lengthException, is(instanceOf(InvalidPasswordLengthException.class)));
    }

    @Test
    void validationExceptions_areIllegalArgumentExceptionsForBackwardCompatibility() {
        assertThrows(IllegalArgumentException.class, () -> OTPValidator.validateSecret(new byte[]{}));
        assertThrows(IllegalArgumentException.class, () -> OTPValidator.validatePasswordLength(5));
        assertThrows(IllegalArgumentException.class, () -> OTPValidator.validateSecretBits(0));
    }
}
