package com.example.pdf_signer;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import java.io.File;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

@Configuration
public class Pkcs11Config {

    private static final Logger log = LoggerFactory.getLogger(Pkcs11Config.class);

    @Getter
    private KeyStore keyStore;

    @Getter
    @Value("${pkcs11.pin}")
    private String pin;

    @Value("${pkcs11.config-path}")
    private String configPath;

    @PostConstruct
    public void initialize() throws Exception {
        String resolvedPath = configPath.startsWith("classpath:")
                ? new File(getClass().getClassLoader().getResource(configPath.substring(10)).toURI()).getAbsolutePath()
                : configPath;
        log.info("PKCS#11 config: {}", resolvedPath);
        Provider prototype = Security.getProvider("SunPKCS11");
        Provider pkcs11Provider = prototype.configure(resolvedPath);
        Security.addProvider(pkcs11Provider);
        keyStore = KeyStore.getInstance("PKCS11", pkcs11Provider);
        keyStore.load(null, pin.toCharArray());
        log.info("PKCS#11 initialized. Has keys: {}", keyStore.aliases().hasMoreElements());
    }
}
