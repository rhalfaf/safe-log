package pl.softr.safelog;

import pl.softr.safelog.masking.EmailMaskingStrategy;
import pl.softr.safelog.masking.FullMaskingStrategy;
import pl.softr.safelog.masking.KeepLast4MaskingStrategy;
import pl.softr.safelog.masking.MaskingStrategy;

import java.lang.reflect.RecordComponent;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;
import java.util.StringJoiner;

public final class SafeLog {

    private static final MaskingStrategy FULL_MASK = new FullMaskingStrategy();
    private static final MaskingStrategy EMAIL_MASK = new EmailMaskingStrategy();
    private static final MaskingStrategy KEEP_LAST_4_MASK = new KeepLast4MaskingStrategy();
    private static final int MAX_RECORD_DEPTH = 10;

    private SafeLog() {
    }

    public static String stringify(Object object) {
        if (object == null) {
            return null;
        }

        Class<?> type = object.getClass();
        if (!type.isRecord()) {
            throw new IllegalArgumentException("SafeLog currently supports only records");
        }

        Set<Object> activeRecords = Collections.newSetFromMap(new IdentityHashMap<>());
        return stringifyRecord(object, activeRecords, 1);
    }

    private static String stringifyRecord(Object object, Set<Object> activeRecords, int depth) {
        if (depth > MAX_RECORD_DEPTH) {
            return "<max-depth>";
        }

        if (!activeRecords.add(object)) {
            return "<cycle>";
        }

        Class<?> type = object.getClass();
        StringJoiner result = new StringJoiner(", ", type.getSimpleName() + "{", "}");
        try {
            for (RecordComponent component : type.getRecordComponents()) {
                Object value = readValue(component, object);
                String renderedValue = renderValue(component, value, activeRecords, depth);
                result.add(component.getName() + "=" + renderedValue);
            }
            return result.toString();
        } finally {
            activeRecords.remove(object);
        }
    }

    private static Object readValue(RecordComponent component, Object object) {
        try {
            return component.getAccessor().invoke(object);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Cannot read component: " + component.getName(), e);
        }
    }

    private static String renderValue(RecordComponent component, Object value, Set<Object> activeRecords, int depth) {
        Sensitive sensitive = component.getAnnotation(Sensitive.class);
        if (value == null) {
            return "null";
        }

        if (value.getClass().isRecord()) {
            return renderNestedRecord(component, value, sensitive, activeRecords, depth);
        }

        if (sensitive != null) {
            String maskedValue = getMaskingStrategy(sensitive.value()).mask(value);
            return escapeControlCharacters(maskedValue);
        }

        return escapeControlCharacters(String.valueOf(value));
    }

    private static String renderNestedRecord(RecordComponent component, Object value, Sensitive sensitive, Set<Object> activeRecords, int depth) {
        if (sensitive == null) {
            return stringifyRecord(value, activeRecords, depth + 1);
        }
        return switch (sensitive.value()) {
            case FULL -> FULL_MASK.mask(value);
            case EMAIL, KEEP_LAST_4 ->
                    throw new IllegalArgumentException("Masking strategy " + sensitive.value() + " cannot be applied to record component: " + component.getName());

        };
    }

    private static MaskingStrategy getMaskingStrategy(MaskType maskType) {
        return switch (maskType) {
            case FULL -> FULL_MASK;
            case EMAIL -> EMAIL_MASK;
            case KEEP_LAST_4 -> KEEP_LAST_4_MASK;
        };
    }

    private static String escapeControlCharacters(String text) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char character = text.charAt(i);
            switch (character) {
                case '\n' -> result.append("\\n");
                case '\r' -> result.append("\\r");
                case '\t' -> result.append("\\t");
                case '\b' -> result.append("\\b");
                case '\f' -> result.append("\\f");
                default -> {
                    if (Character.isISOControl(character)) {
                        result.append("\\u%04X".formatted((int) character));
                    } else {
                        result.append(character);
                    }
                }
            }
        }
        return result.toString();
    }
}
