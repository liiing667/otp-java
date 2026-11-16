package com.bastiaanjansen.otp.helpers;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class URIHelperTest {

    @Test
    void queryItemsWithOneQueryItem() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?algorithm=SHA1");
        Map<String, String> query = URIHelper.queryItems(uri);
        String expected = "SHA1";

        assertThat(query.get("algorithm"), is(expected));
    }

    @Test
    void queryItemsWithTwoQueryItems() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?algorithm=SHA1&secret=ABC");
        Map<String, String> query = URIHelper.queryItems(uri);
        String expected = "ABC";

        assertThat(query.get("secret"), is(expected));
    }

    @Test
    void queryItemsWithEncodedSeparatorsInValue() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?issuer=mac%26cheese&secret=ABC%3DD");
        Map<String, String> query = URIHelper.queryItems(uri);

        assertThat(query.get("issuer"), is("mac&cheese"));
        assertThat(query.get("secret"), is("ABC=D"));
    }

    @Test
    void queryItemsWithoutQuery_returnsEmptyMap() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account");

        assertThat(URIHelper.queryItems(uri).isEmpty(), is(true));
    }

    @Test
    void queryItemsWithDuplicateParameter_throwsIllegalArgumentException() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?secret=ABC&secret=DEF");

        assertThrows(IllegalArgumentException.class, () -> URIHelper.queryItems(uri));
    }

    @Test
    void queryItemsWithDuplicateEncodedParameter_throwsIllegalArgumentException() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?secret=ABC&%73ecret=DEF");

        assertThrows(IllegalArgumentException.class, () -> URIHelper.queryItems(uri));
    }

    @Test
    void parseLabelWithIssuerAndAccount() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?secret=ABC");
        String[] label = URIHelper.parseLabel(uri);

        assertThat(label[0], is("issuer"));
        assertThat(label[1], is("account"));
    }

    @Test
    void parseLabelWithoutIssuer() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/account?secret=ABC");
        String[] label = URIHelper.parseLabel(uri);

        assertThat(label[0], is((String) null));
        assertThat(label[1], is("account"));
    }

    @Test
    void parseLabelWithEncodedColonAndPercentSign() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/Issuer%3ASub:user%2540example.com?secret=ABC");
        String[] label = URIHelper.parseLabel(uri);

        assertThat(label[0], is("Issuer:Sub"));
        assertThat(label[1], is("user%40example.com"));
    }

    @Test
    void parseLabelWithoutLabel() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/?secret=ABC");
        String[] label = URIHelper.parseLabel(uri);

        assertThat(label[0], is((String) null));
        assertThat(label[1], is((String) null));
    }

    @Test
    void validateOTPAuthTypeWithWrongScheme_throwsIllegalArgumentException() throws URISyntaxException {
        URI uri = new URI("https://totp/issuer:account?secret=ABC");

        assertThrows(IllegalArgumentException.class, () -> URIHelper.validateOTPAuthType(uri, "totp"));
    }

    @Test
    void validateOTPAuthTypeWithWrongType_throwsIllegalArgumentException() throws URISyntaxException {
        URI uri = new URI("otpauth://hotp/issuer:account?secret=ABC");

        assertThrows(IllegalArgumentException.class, () -> URIHelper.validateOTPAuthType(uri, "totp"));
    }

    @Test
    void validateOTPAuthTypeWithMatchingType_doesNotThrow() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?secret=ABC");

        assertDoesNotThrow(() -> URIHelper.validateOTPAuthType(uri, "totp"));
    }

    @Test
    void createURI_doesNotThrow() {
        Map<String, String> query = new HashMap<>();

        assertDoesNotThrow(() -> URIHelper.createURI("scheme", "host", "path", query));
    }

    @Test
    void createURIWithoutQueryItems() throws URISyntaxException {
        Map<String, String> query = new HashMap<>();
        URI uri = URIHelper.createURI("scheme", "host", "path", query);
        String expected = "scheme://host/path";

        assertThat(uri.toString(), is(expected));
    }

    @Test
    void encodeAndDecodeRoundTrip() {
        String value = "mac&cheese: 100% legit?";

        assertThat(URIHelper.decode(URIHelper.encode(value)), is(value));
    }

    @Test
    void createURIWithOneQueryItem() throws URISyntaxException {
        Map<String, String> query = new HashMap<>();
        query.put("test", "1");
        URI uri = URIHelper.createURI("scheme", "host", "path", query);
        String expected = "scheme://host/path?test=1";

        assertThat(uri.toString(), is(expected));
    }

    @Test
    void createURIWithTwoQueryItems() throws URISyntaxException {
        Map<String, String> query = new HashMap<>();
        query.put("test", "1");
        query.put("test2", "2");
        URI uri = URIHelper.createURI("scheme", "host", "path", query);
        String expected = "scheme://host/path?test2=2&test=1";

        assertThat(uri.toString(), is(expected));
    }

    @Test
    void createURIWithUrlUnsafeCharacters() throws URISyntaxException {
        Map<String, String> query = new HashMap<>();
        query.put("test", "value 1");
        query.put("test2", "value?&2");
        URI uri = URIHelper.createURI("scheme", "host", "path", query);
        String expected = "scheme://host/path?test2=value%3F%262&test=value%201";

        assertThat(uri.toString(), is(expected));
    }
}
