import java.security.*;

public class Pkcs11ServicesList {
    public static void main(String[] args) throws Exception {
        Provider prototype = Security.getProvider("SunPKCS11");
        Provider p = prototype.configure(
            "/mnt/c/Users/Mr Robot/Downloads/pdf-signer/pdf-signer/src/main/resources/pkcs11.cfg");
        Security.addProvider(p);
        System.out.println("Provider: " + p.getName());
        System.out.println("--- Cipher Services ---");
        p.getServices().stream()
            .filter(s -> "Cipher".equals(s.getType()))
            .forEach(s -> System.out.println(s.getAlgorithm()));
        System.out.println("--- Signature Services ---");
        p.getServices().stream()
            .filter(s -> "Signature".equals(s.getType()))
            .forEach(s -> System.out.println(s.getAlgorithm()));
    }
}
