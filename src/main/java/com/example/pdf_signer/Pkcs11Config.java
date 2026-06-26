package com.example.pdf_signer;

import jakarta.annotation.PostConstruct;
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

    private KeyStore keyStore;
    private KeyStore rootCaKeyStore;

    @Value("${pkcs11.config-path}")
    private String configPath;

    @Value("${pkcs11.pin}")
    private String pin;

    @PostConstruct
    public void initialize() throws Exception {
        // Initialize Signer token
        keyStore = initToken(configPath, pin, "Signer");
        log.info("Signer token ready. Has keys: {}", keyStore.aliases().hasMoreElements());

        // Initialize Root CA token (if config exists)
        try {
            String rootCfgPath = "classpath:pkcs11-rootca.cfg";
            rootCaKeyStore = initToken(rootCfgPath, "9999", "RootCA");
            log.info("Root CA token ready. Has objects: {}", rootCaKeyStore.aliases().hasMoreElements());
        } catch (Exception e) {
            log.warn("Root CA token not available: {}", e.getMessage());
        }
    }

    private KeyStore initToken(String cfgPath, String tokenPin, String name) throws Exception {
        String resolvedPath = cfgPath.startsWith("classpath:")
                ? new File(getClass().getClassLoader().getResource(cfgPath.substring(10)).toURI()).getAbsolutePath()
                : cfgPath;

        log.info("{} config: {}", name, resolvedPath);

        Provider prototype = Security.getProvider("SunPKCS11");
        Provider provider = prototype.configure(resolvedPath);
        Security.addProvider(provider);

        KeyStore ks = KeyStore.getInstance("PKCS11", provider);
        ks.load(null, tokenPin.toCharArray());
        return ks;
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }

    public KeyStore getRootCaKeyStore() {
        return rootCaKeyStore;
    }

    public String getPin() {
        return pin;
    }
}
