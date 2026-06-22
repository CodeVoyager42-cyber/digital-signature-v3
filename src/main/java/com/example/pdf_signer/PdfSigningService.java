package com.example.pdf_signer;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collections;

@Service
public class PdfSigningService {

    private static final Logger log = LoggerFactory.getLogger(PdfSigningService.class);
    private final Pkcs11Config pkcs11Config;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public PdfSigningService(Pkcs11Config pkcs11Config) {
        this.pkcs11Config = pkcs11Config;
    }

    public byte[] signPdf(byte[] pdfBytes) throws Exception {
        KeyStore keyStore = pkcs11Config.getKeyStore();
        String alias = keyStore.aliases().nextElement();
        KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(
                alias, new KeyStore.PasswordProtection(pkcs11Config.getPin().toCharArray()));
        
        PrivateKey pk = entry.getPrivateKey();
        X509Certificate cert = (X509Certificate) entry.getCertificate();
        X509Certificate[] chain = new X509Certificate[]{cert};

        Provider pkcs11Prov = Security.getProvider("SunPKCS11-SoftHSM");

        try (PDDocument doc = Loader.loadPDF(pdfBytes)) {
            PDSignature sig = new PDSignature();
            sig.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            sig.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            sig.setName("Digital Signer");
            sig.setReason("Document Signing");
            sig.setSignDate(Calendar.getInstance());

            SignatureOptions opts = new SignatureOptions();
            // No visible signature – digital signature only

            doc.addSignature(sig, new Pkcs11Signer(pk, chain, pkcs11Prov), opts);

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.saveIncremental(out);
            return out.toByteArray();
        }
    }

    static class Pkcs11Signer implements SignatureInterface {
        private final PrivateKey pk;
        private final X509Certificate[] chain;
        private final Provider pkcs11Prov;

        Pkcs11Signer(PrivateKey pk, X509Certificate[] chain, Provider pkcs11Prov) {
            this.pk = pk;
            this.chain = chain;
            this.pkcs11Prov = pkcs11Prov;
        }

        @Override
        public byte[] sign(InputStream content) throws IOException {
            try {
                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                byte[] tmp = new byte[8192];
                int n;
                while ((n = content.read(tmp)) != -1) buf.write(tmp, 0, n);
                byte[] data = buf.toByteArray();

                // Sign with PKCS#11
                Signature tokenSigner = Signature.getInstance("SHA256withRSA", pkcs11Prov);
                tokenSigner.initSign(pk);
                tokenSigner.update(data);
                byte[] signatureValue = tokenSigner.sign();

                // Build CMS
                AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
                        .find("SHA256withRSA");
                ContentSigner contentSigner = new ContentSigner() {
                    private final ByteArrayOutputStream os = new ByteArrayOutputStream();
                    @Override
                    public AlgorithmIdentifier getAlgorithmIdentifier() { return sigAlgId; }
                    @Override
                    public OutputStream getOutputStream() { return os; }
                    @Override
                    public byte[] getSignature() { return signatureValue; }
                };

                CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
                gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()
                ).build(contentSigner, chain[0]));
                gen.addCertificates(new JcaCertStore(Collections.singletonList(chain[0])));
                return gen.generate(new CMSProcessableByteArray(data), false).getEncoded();
            } catch (Exception e) {
                throw new IOException("Sign failed: " + e.getMessage(), e);
            }
        }
    }
}
