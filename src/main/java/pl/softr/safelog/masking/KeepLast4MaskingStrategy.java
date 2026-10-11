package pl.softr.safelog.masking;

public class KeepLast4MaskingStrategy implements MaskingStrategy {
    @Override
    public String mask(Object object) {
        if (object == null) {
            return "null";
        }
        String text = String.valueOf(object);
        if (text.length() <= 4) {
            return "****";
        }
        String visiblePart = text.substring(text.length() - 4);
        return "*".repeat(text.length() - 4) + visiblePart;
    }
}
