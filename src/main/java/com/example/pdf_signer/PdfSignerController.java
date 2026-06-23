package com.example.pdf_signer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class PdfSignerController {

    private static final Logger log = LoggerFactory.getLogger(PdfSignerController.class);
    private final PdfSigningService signingService;

    public PdfSignerController(PdfSigningService signingService) {
        this.signingService = signingService;
    }

    @GetMapping("/")
    public ResponseEntity<String> home() {
        String html = "<!DOCTYPE html><html><head><title>PDF Signer</title></head><body>" +
            "<h1>PDF Digital Signature</h1>" +
            "<form action='/sign' method='post' enctype='multipart/form-data'>" +
            "<input type='file' name='file' accept='.pdf' required><br><br>" +
            "<button type='submit'>Sign PDF</button>" +
            "</form></body></html>";
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(html);
    }

    @PostMapping("/sign")
    public ResponseEntity<?> sign(@RequestParam("file") MultipartFile file) {
        try {
            log.info("Signing file: {}", file.getOriginalFilename());
            byte[] signed = signingService.signPdf(file.getBytes());
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_PDF);
            headers.setContentDisposition(ContentDisposition.attachment()
                    .filename("signed_" + file.getOriginalFilename()).build());
            return ResponseEntity.ok().headers(headers).body(signed);
        } catch (Exception e) {
            log.error("Error: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body("{\"error\":\"" + e.getMessage() + "\"}");
        }
    }

    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("OK - Service is running");
    }
}
