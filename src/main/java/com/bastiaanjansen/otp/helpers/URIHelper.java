package com.bastiaanjansen.otp.helpers;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * A URI utility class with helper methods
 *
 * @author Bastiaan Jansen
 */
public class URIHelper {
    
    public static final String DIGITS = "digits";
    public static final String SECRET = "secret";
    public static final String ALGORITHM = "algorithm";
    public static final String PERIOD = "period";
    public static final String COUNTER = "counter";
    public static final String ISSUER = "issuer";

    private static final String OTPAUTH_SCHEME = "otpauth";

    private URIHelper() {}

    /**
     * Get a map of query items from URI
     * <p>
     * The raw (still encoded) query is split on '&amp;' and '=' boundaries before decoding, so
     * percent-encoded separators inside a value (for example %26 and %3D) cannot shift parameter
     * boundaries. Duplicate parameter names are rejected instead of silently overwriting earlier
     * values.
     *
     * @param uri to get query items from
     * @return map of query items from URI
     * @throws IllegalArgumentException when a query parameter occurs more than once
     */
    public static Map<String, String> queryItems(URI uri) {
        Map<String, String> items = new LinkedHashMap<>();
        String query = uri.getRawQuery();
        if (query == null || query.isEmpty()) return items;

        String[] pairs = query.split("&");

        for (String pair: pairs) {
            if (pair.isEmpty()) continue;

            int index = pair.indexOf("=");
            String key = decode(index < 0 ? pair : pair.substring(0, index));
            String value = index < 0 ? "" : decode(pair.substring(index + 1));

            if (items.putIfAbsent(key, value) != null)
                throw new IllegalArgumentException("Duplicate query parameter: " + key);
        }
        return items;
    }

    /**
     * Parse the label of an otpauth URI into its issuer and account name components.
     * <p>
     * The label is split on the first literal colon of the raw (still encoded) path, so
     * percent-encoded colons (%3A) inside a component cannot shift the issuer/account boundary.
     * Each component is decoded afterwards. A label without a colon only holds an account name.
     *
     * @param uri otpauth URI to parse the label from
     * @return two-element array with the issuer (or null when absent) at index 0 and the account
     * name (or null when absent) at index 1
     */
    public static String[] parseLabel(URI uri) {
        String path = uri.getRawPath();
        if (path == null) return new String[]{null, null};

        String label = path.startsWith("/") ? path.substring(1) : path;
        if (label.isEmpty()) return new String[]{null, null};

        int separator = label.indexOf(':');
        if (separator < 0) return new String[]{null, decode(label)};

        String issuer = decode(label.substring(0, separator));
        String account = decode(label.substring(separator + 1));

        return new String[]{issuer.isEmpty() ? null : issuer, account.isEmpty() ? null : account};
    }

    /**
     * Validate that a URI is an otpauth URI of the expected OTP type
     *
     * @param uri to validate
     * @param expectedType expected OTP type (for example totp or hotp)
     * @throws IllegalArgumentException when the scheme is not otpauth or the type does not match
     */
    public static void validateOTPAuthType(URI uri, String expectedType) {
        if (!OTPAUTH_SCHEME.equalsIgnoreCase(uri.getScheme()))
            throw new IllegalArgumentException("URI scheme must be " + OTPAUTH_SCHEME);

        String type = uri.getHost();
        if (type == null || !type.equalsIgnoreCase(expectedType))
            throw new IllegalArgumentException("URI type must be " + expectedType);
    }

    /**
     * Create a URI based on a scheme, host, path and query items
     *
     * @param scheme of URI
     * @param host of URI
     * @param path of URI
     * @param query of URI
     * @return created URI
     * @throws URISyntaxException when URI cannot be created
     */
    public static URI createURI(String scheme, String host, String path, Map<String, String> query) throws URISyntaxException {
        String uriString = String.format("%s://%s/%s", scheme, host, path);

        if (!query.isEmpty()) {
            uriString = query.keySet().stream()
                    .map(key -> String.format("%s=%s", key, encode(query.get(key))))
                    .collect(Collectors.joining("&", uriString + "?", ""));
        }

        return new URI(uriString);
    }

    public static String encode(String value) {
        try {
            // Standard URLEncoder uses + for spaces (application/x-www-form-urlencoded)
            // We replace it with %20 to comply with URI spec (RFC 3986)
            return URLEncoder.encode(value, StandardCharsets.UTF_8.name())
                    .replace("+", "%20");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    public static String decode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8.toString());
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Encoding should be supported");
        }
    }
}
