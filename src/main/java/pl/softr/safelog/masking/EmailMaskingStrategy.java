package pl.softr.safelog.masking;

public class EmailMaskingStrategy implements MaskingStrategy {
    @Override
    public String mask(Object object) {
        if (object == null) {
            return "null";
        }
        String email = String.valueOf(object);
        int atIndex = email.indexOf("@");
        if (atIndex < 0) {
            return "****";
        }
        String firstCharacter = email.substring(0, 1);
        String domain = email.substring(atIndex);
        return firstCharacter + "****" + domain;
    }
}
