package com.example.pdf_signer;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
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

        try (PDDocument doc = Loader.loadPDF(pdfBytes)) {
            PDSignature sig = new PDSignature();
            sig.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            sig.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            sig.setName("Digital Signer");
            sig.setReason("Document Signing");
            sig.setSignDate(Calendar.getInstance());

            SignatureOptions opts = new SignatureOptions();
            doc.addSignature(sig, new Pkcs11Signer(pk, chain), opts);

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.saveIncremental(out);
            return out.toByteArray();
        }
    }

    static class Pkcs11Signer implements SignatureInterface {
        private final PrivateKey pk;
        private final X509Certificate[] chain;

        Pkcs11Signer(PrivateKey pk, X509Certificate[] chain) {
            this.pk = pk;
            this.chain = chain;
        }

        @Override
        public byte[] sign(InputStream content) throws IOException {
            try {
                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                byte[] tmp = new byte[8192];
                int n;
                while ((n = content.read(tmp)) != -1) buf.write(tmp, 0, n);
                byte[] data = buf.toByteArray();

                // Find PKCS#11 provider
                Provider pkcs11Prov = null;
                for (Provider p : Security.getProviders()) {
                    if (p.getName().contains("PKCS11")) { pkcs11Prov = p; break; }
                }

                // Compute SHA-256 hash
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(data);

                // Build DigestInfo structure: SEQUENCE { AlgorithmIdentifier, OCTET STRING hash }
                byte[] digestInfo = createDigestInfo(hash, new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1")); // SHA-256 OID
                
                // Use Cipher with RSA/ECB/PKCS1Padding to sign the DigestInfo
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", pkcs11Prov);
                cipher.init(Cipher.ENCRYPT_MODE, pk);
                byte[] signatureValue = cipher.doFinal(digestInfo);

                // Build CMS
                CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
                ContentSigner contentSigner = new ContentSigner() {
                    private final ByteArrayOutputStream os = new ByteArrayOutputStream();
                    @Override
                    public AlgorithmIdentifier getAlgorithmIdentifier() {
                        return new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11")); // rsaEncryption
                    }
                    @Override
                    public OutputStream getOutputStream() { return os; }
                    @Override
                    public byte[] getSignature() { return signatureValue; }
                };

                gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()
                ).build(contentSigner, chain[0]));
                gen.addCertificates(new JcaCertStore(Collections.singletonList(chain[0])));
                return gen.generate(new CMSProcessableByteArray(data), false).getEncoded();
            } catch (Exception e) {
                throw new IOException("Sign failed: " + e.getMessage(), e);
            }
        }

        private static byte[] createDigestInfo(byte[] hash, ASN1ObjectIdentifier hashOid) throws IOException {
            org.bouncycastle.asn1.x509.AlgorithmIdentifier algId = new org.bouncycastle.asn1.x509.AlgorithmIdentifier(hashOid);
            org.bouncycastle.asn1.DEROctetString octetString = new org.bouncycastle.asn1.DEROctetString(hash);
            org.bouncycastle.asn1.ASN1EncodableVector v = new org.bouncycastle.asn1.ASN1EncodableVector();
            v.add(algId);
            v.add(octetString);
            return new org.bouncycastle.asn1.DERSequence(v).getEncoded();
        }
    }
}
