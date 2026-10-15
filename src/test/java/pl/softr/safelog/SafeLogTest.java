package pl.softr.safelog;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SafeLogTest {

    @Test
    void shouldMaskSensitiveComponent() {
        User user = new User("admin", "admin@safelog.pl", "Warsaw", "12345678901");
        String result = SafeLog.stringify(user);
        assertEquals("User{name=admin, email=a****@safelog.pl, cityName=**rsaw, pesel=****}", result);
    }

    @Test
    void shouldEscapeControlCharacters() {
        LogEntry logEntry = new LogEntry("line1\nline2\r\t\b\f\u001B\u007Fend");
        String result = SafeLog.stringify(logEntry);
        assertEquals(
                "LogEntry{message=line1\\nline2\\r\\t\\b\\f\\u001B\\u007Fend}",
                result
        );
    }

    @Test
    void shouldThrowExceptionWhenObjectIsRecord() {
        assertThrows(IllegalArgumentException.class, () -> SafeLog.stringify(new Object()));
    }

    @Test
    void shouldReturnStringifyNullWhenObjectElementIsNull() {
        User user = new User(null, null, null, null);
        String result = SafeLog.stringify(user);
        assertEquals("User{name=null, email=null, cityName=null, pesel=null}", result);
    }

    @Test
    void shouldReturnFullyMaskedStringWhenEmailIsIncorrect() {
        User user = new User("admin", "admin$safelog.pl", "Warsaw", "12345678901");
        String result = SafeLog.stringify(user);
        assertEquals("User{name=admin, email=****, cityName=**rsaw, pesel=****}", result);
    }

    @Test
    void shouldReturnFullyMaskedStringWhenLast4MaskingStrategyWithStringEqualsOrShortenThan4
            () {
        User user1 = new User("admin", "admin$safelog.pl", "Koło", "12345678901");
        User user2 = new User("admin", "admin$safelog.pl", "Dół", "12345678901");
        String result1 = SafeLog.stringify(user1);
        String result2 = SafeLog.stringify(user2);
        assertEquals("User{name=admin, email=****, cityName=****, pesel=****}", result1);
        assertEquals("User{name=admin, email=****, cityName=****, pesel=****}", result2);
    }

    @Test
    void shouldPreservePolishCharactersAndEmoji() {
        UnicodeEntry entry = new UnicodeEntry("Zażółć gęślą jaźń 😀🚀");
        String result = SafeLog.stringify(entry);
        assertEquals("UnicodeEntry{message=Zażółć gęślą jaźń 😀🚀}", result
        );
    }

    @Test
    void shouldEscapeControlCharactersRemainingAfterEmailMasking() {
        User user = new User("admin", "admin@example.com\r\nFAKE\tERROR\u001B\"", "Koło", "12345678901");
        String result = SafeLog.stringify(user);
        assertEquals("User{name=admin, email=a****@example.com\\r\\nFAKE\\tERROR\\u001B\", cityName=****, pesel=****}", result);
    }

    @Test
    void shouldRecursivelyMaskSensitiveComponentsInNestedRecords() {
        Credentials credentials = new Credentials("admin", "secret-password", null, null);
        LoginEvent event = new LoginEvent("login", credentials);
        String result = SafeLog.stringify(event);
        assertEquals("LoginEvent{action=login, credentials=Credentials{username=admin, password=****, recoveryEmail=null, cardNumber=null}}", result);
    }

    @Test
    void shouldApplyDifferentMaskingStrategiesInsideNestedRecord() {
        Credentials credentials = new Credentials(
                "admin",
                "secret-password",
                "admin@example.com",
                "1234567890123456"
        );

        LoginEvent event = new LoginEvent(
                "login",
                credentials
        );

        String result = SafeLog.stringify(event);

        assertEquals(
                "LoginEvent{action=login, " +
                        "credentials=Credentials{" +
                        "username=admin, " +
                        "password=****, " +
                        "recoveryEmail=a****@example.com, " +
                        "cardNumber=************3456}}",
                result
        );
    }

    @Test
    void shouldMaskWholeNestedRecordWithFullStrategy() {
        Credentials credentials = new Credentials(
                "admin",
                "secret-password",
                "admin@example.com",
                "1234567890123456"
        );
        ProtectedEvent event = new ProtectedEvent(credentials);
        String result = SafeLog.stringify(event);
        assertEquals("ProtectedEvent{credentials=****}", result);
    }

    @Test
    void shouldRejectEmailStrategyAppliedToNestedRecord() {
        Credentials credentials = new Credentials(
                "admin",
                "secret-password",
                "admin@example.com",
                "1234567890123456"
        );

        InvalidEmailEvent event = new InvalidEmailEvent(credentials);
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> SafeLog.stringify(event)
        );
        assertEquals("Masking strategy EMAIL cannot be applied " +
                "to record component: credentials", exception.getMessage()
        );
    }

    @Test
    void shouldRejectKeepLast4StrategyAppliedToNestedRecord() {
        Credentials credentials = new Credentials(
                "admin",
                "secret-password",
                "admin@example.com",
                "1234567890123456"
        );

        InvalidKeepLast4Event event = new InvalidKeepLast4Event(credentials);
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> SafeLog.stringify(event)
        );
        assertEquals("Masking strategy KEEP_LAST_4 cannot be applied " +
                "to record component: credentials", exception.getMessage()
        );
    }

    private record Credentials(
            String username,

            @Sensitive(MaskType.FULL)
            String password,

            @Sensitive(MaskType.EMAIL)
            String recoveryEmail,

            @Sensitive(MaskType.KEEP_LAST_4)
            String cardNumber) {
    }

    private record LoginEvent(
            String action,
            Credentials credentials) {
    }

    private record ProtectedEvent(
            @Sensitive(MaskType.FULL)
            Credentials credentials) {
    }

    private record InvalidEmailEvent(
            @Sensitive(MaskType.EMAIL)
            Credentials credentials) {
    }

    private record InvalidKeepLast4Event(
            @Sensitive(MaskType.KEEP_LAST_4)
            Credentials credentials) {
    }

    private record User(String name,
                        @Sensitive(value = MaskType.EMAIL) String email,
                        @Sensitive(value = MaskType.KEEP_LAST_4) String cityName,
                        @Sensitive(value = MaskType.FULL) String pesel) {

        @Override
        public String toString() {
            throw new AssertionError("toSting() should never be called");
        }
    }

    private record LogEntry(String message) {
    }

    private record UnicodeEntry(String message) {
    }

    @Test
    void shouldStopProcessingRecordsAfterMaximumDepth() {
        Object atMaximumDepth =
                new DeepestRecord("secret-value");

        // Dziewięć opakowań + DeepestRecord daje łącznie 10 poziomów.
        for (int i = 0; i < 9; i++) {
            atMaximumDepth = new NestedRecord(atMaximumDepth);
        }

        String resultAtLimit =
                SafeLog.stringify(atMaximumDepth);

        assertTrue(resultAtLimit.contains("secret-value"));
        assertFalse(resultAtLimit.contains("<max-depth>"));

        // Dodatkowe opakowanie przesuwa DeepestRecord na poziom 11.
        Object aboveMaximumDepth =
                new NestedRecord(atMaximumDepth);

        String resultAboveLimit =
                SafeLog.stringify(aboveMaximumDepth);

        assertTrue(resultAboveLimit.contains("<max-depth>"));
        assertFalse(resultAboveLimit.contains("secret-value"));
    }

    private record NestedRecord(Object value) {
    }

    private record DeepestRecord(String value) {
    }

}
