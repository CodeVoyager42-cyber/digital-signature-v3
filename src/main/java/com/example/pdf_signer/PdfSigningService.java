package com.example.pdf_signer;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;

@Service
public class PdfSigningService {

    private static final Logger log = LoggerFactory.getLogger(PdfSigningService.class);
    private final Pkcs11Config pkcs11Config;

    private static final String SIGNER_NAME = "Mouad EL BAHRAOUI";
    private static final String SIGNER_REASON = "Document Officiel";
    private static final String SIGNER_LOCATION = "Rabat, Morocco";

    private static final String[] TSA_SERVERS = {
        "http://timestamp.digicert.com",
        "http://timestamp.sectigo.com",
        "http://tsa.starfieldtech.com"
    };

    private static final int TSA_TIMEOUT_MS = 10000;

    static { Security.addProvider(new BouncyCastleProvider()); }

    public PdfSigningService(Pkcs11Config pkcs11Config) {
        this.pkcs11Config = pkcs11Config;
    }

    public byte[] signPdf(byte[] pdfBytes) throws Exception {
        KeyStore keyStore = pkcs11Config.getKeyStore();
        String alias = keyStore.aliases().nextElement();
        KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(
                alias, new KeyStore.PasswordProtection(pkcs11Config.getPin().toCharArray()));

        PrivateKey pk = entry.getPrivateKey();
        X509Certificate signerCert = (X509Certificate) entry.getCertificate();

        List<X509Certificate> chainList = new ArrayList<>();
        chainList.add(signerCert);
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate rootCert = (X509Certificate) cf.generateCertificate(
                    new FileInputStream("/home/mouad/isicod-ca-cert.pem"));
            chainList.add(rootCert);
        } catch (Exception e) {}

        X509Certificate[] chain = chainList.toArray(new X509Certificate[0]);
        Provider pkcs11Prov = Security.getProvider("SunPKCS11-SoftHSM");

        try (PDDocument doc = Loader.loadPDF(pdfBytes)) {
            PDSignature sig = new PDSignature();
            sig.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            sig.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            sig.setName(SIGNER_NAME);
            sig.setReason(SIGNER_REASON);
            sig.setLocation(SIGNER_LOCATION);
            sig.setSignDate(Calendar.getInstance()); // Set local time, TSA overrides

            doc.addSignature(sig, new Pkcs11Signer(pk, chain, pkcs11Prov), new SignatureOptions());

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.saveIncremental(out);
            return out.toByteArray();
        }
    }

    static class Pkcs11Signer implements SignatureInterface {
        private final PrivateKey pk;
        private final X509Certificate[] chain;
        private final Provider pkcs11Prov;
        private static final Logger log = LoggerFactory.getLogger(Pkcs11Signer.class);

        Pkcs11Signer(PrivateKey pk, X509Certificate[] chain, Provider pkcs11Prov) {
            this.pk = pk; this.chain = chain; this.pkcs11Prov = pkcs11Prov;
        }

        @Override
        public byte[] sign(InputStream content) throws IOException {
            try {
                byte[] data = content.readAllBytes();

                // Sign with PKCS#11
                ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                        .setProvider(pkcs11Prov).build(pk);

                // Get TSA timestamp
                byte[] timestampToken = getTimestampToken(data);

                // Build CMS
                CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
                gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()
                ).build(contentSigner, chain[0]));

                gen.addCertificates(new JcaCertStore(Arrays.asList(chain)));

                CMSSignedData signedData = gen.generate(new CMSProcessableByteArray(data), false);

                // If we have a timestamp, log it
                if (timestampToken != null) {
                    TimeStampResponse tsResponse = new TimeStampResponse(timestampToken);
                    TimeStampToken tsToken = tsResponse.getTimeStampToken();
                    log.info("Document timestamped at: {}", tsToken.getTimeStampInfo().getGenTime());
                }

                return signedData.getEncoded();
            } catch (Exception e) {
                log.error("Sign failed", e);
                throw new IOException("Sign failed: " + e.getMessage(), e);
            }
        }

        private byte[] getTimestampToken(byte[] data) {
            for (String tsaUrl : TSA_SERVERS) {
                try {
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    byte[] hash = digest.digest(data);

                    TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
                    reqGen.setCertReq(true);
                    TimeStampRequest request = reqGen.generate(
                            new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"),
                            hash, BigInteger.valueOf(100));

                    byte[] requestBytes = request.getEncoded();
                    URL url = new URL(tsaUrl);
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                    conn.setDoOutput(true);
                    conn.setRequestMethod("POST");
                    conn.setRequestProperty("Content-Type", "application/timestamp-query");
                    conn.setRequestProperty("Content-Length", String.valueOf(requestBytes.length));
                    conn.setConnectTimeout(TSA_TIMEOUT_MS);
                    conn.setReadTimeout(TSA_TIMEOUT_MS);

                    try (OutputStream out = conn.getOutputStream()) {
                        out.write(requestBytes); out.flush();
                    }

                    if (conn.getResponseCode() != 200) continue;

                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    try (InputStream in = conn.getInputStream()) {
                        byte[] buffer = new byte[4096]; int n;
                        while ((n = in.read(buffer)) != -1) baos.write(buffer, 0, n);
                    }

                    TimeStampResponse response = new TimeStampResponse(baos.toByteArray());
                    response.validate(request);
                    if (response.getTimeStampToken() != null) {
                        return baos.toByteArray();
                    }
                } catch (Exception e) {
                    log.warn("TSA {} failed: {}", tsaUrl, e.getMessage());
                }
            }
            return null;
        }
    }
}
