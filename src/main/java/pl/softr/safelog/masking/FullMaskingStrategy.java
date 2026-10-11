package pl.softr.safelog.masking;

public class FullMaskingStrategy implements MaskingStrategy {
    @Override
    public String mask(Object object) {
        if (object == null) {
            return "null";
        }
        return "****";
    }
}
