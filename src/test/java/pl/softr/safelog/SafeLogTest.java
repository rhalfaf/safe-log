package pl.softr.safelog;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
    void shouldReturnNullWhenObjectIsNull() {
        String result = SafeLog.stringify(null);
        assertEquals(null, result);
    }

    @Test
    void shouldThrowExceptionWhenObjectIsNotNull() {
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
    void shouldReturnFullyMaskedStringWhenLast4MaskingStrategyWithStringEqualsOrShortenThan$() {
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
        User user = new User("admin", "\"admin@example.com\\r\\nFAKE\\tERROR\\u001B\"", "Koło", "12345678901");
        String result = SafeLog.stringify(user);
        assertEquals("User{name=admin, email=\"****@example.com\\r\\nFAKE\\tERROR\\u001B\", cityName=****, pesel=****}",result);
    }

    @Test
    void shouldRecursivelyMaskSensitiveComponentsInNestedRecords() {
        Credentials credentials = new Credentials("admin", "secret-password");
        LoginEvent event = new LoginEvent("login", credentials);

        String result = SafeLog.stringify(event);

        assertEquals(
                "LoginEvent{action=login, credentials=Credentials{username=admin, password=****}}",
                result
        );
    }

    @Test
    void shouldMaskWholeNestedRecordWhenParentComponentIsSensitive() {
        Credentials credentials = new Credentials("admin", "secret-password");
        ProtectedEvent event = new ProtectedEvent(credentials);

        String result = SafeLog.stringify(event);
        System.out.println(result);
        assertEquals("ProtectedEvent{credentials=****}", result);
    }

    @Test
    void shouldStopProcessingRecordsAfterMaximumDepth() {
        Object nestedRecord = new Credentials("admin", "secret-password");
        for (int i = 0; i < 10; i++) {
            nestedRecord = new NestedRecord(nestedRecord);
        }

        String result = SafeLog.stringify(nestedRecord);

        assertTrue(result.contains("<max-depth>"));
        assertFalse(result.contains("secret-password"));
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

    private record Credentials(
            String username,
            @Sensitive String password
    ) {
    }

    private record LoginEvent(String action, Credentials credentials) {
    }

    private record ProtectedEvent(@Sensitive Credentials credentials) {
    }

    private record NestedRecord(Object value) {
    }

}
