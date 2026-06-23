package com.example.pdf_signer;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;

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
                // 1. Let Bouncy Castle build a ContentSigner backed directly by your PKCS#11 Token
                ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                        .setProvider(pkcs11Prov)
                        .build(pk);

                // 2. Initialize the CMS generator
                CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
                gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()
                ).build(contentSigner, chain[0]));
                
                gen.addCertificates(new JcaCertStore(Arrays.asList(chain)));

                // 3. Process the stream contents directly without allocating massive memory arrays
                CMSProcessableInputStream msg = new CMSProcessableInputStream(content);
                
                // 4. Generate the detached signature block (encapsulate = false)
                CMSSignedData signedData = gen.generate(msg, false);
                return signedData.getEncoded();
                
            } catch (Exception e) {
                log.error("Cryptographic signing processing failed", e);
                throw new IOException("Sign failed: " + e.getMessage(), e);
            }
        }
    }

    /**
     * Efficient helper to pipe PDF byte ranges into BouncyCastle's hashing blocks
     * without duplicating content ranges in memory.
     */
    private static class CMSProcessableInputStream implements CMSTypedData {
        private final InputStream in;

        public CMSProcessableInputStream(InputStream in) {
            this.in = in;
        }

        @Override
        public ASN1ObjectIdentifier getContentType() {
            return CMSObjectIdentifiers.data;
        }

        @Override
        public void write(OutputStream out) throws IOException, CMSException {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
        }

        @Override
        public Object getContent() {
            return in;
        }
    }
}
