//
//  ViewController.m
//  openssl-pinning
//
//  Created by Daniel Mayer on 12/17/14.
//  Copyright (c) 2014 Daniel A. Mayer. All rights reserved.
//

#import "ViewController.h"

@interface ViewController ()

@property (weak, nonatomic) IBOutlet UILabel *label;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


/* Extracts the Content-Length from HTTP Headers */
int extract_content_length(char response[]) {
    
    NSArray *headers = [[NSString stringWithCString:response encoding:NSASCIIStringEncoding] componentsSeparatedByString:@"\r\n"];
    
    NSString *filter = @"SELF BEGINSWITH %@";
    NSPredicate* predicate = [NSPredicate predicateWithFormat:filter, @"Content-Length"];

    NSArray* filteredData = [headers filteredArrayUsingPredicate:predicate];
    
    NSString *length = [[filteredData.firstObject componentsSeparatedByString:@":"] objectAtIndex:1];
    
    return [length intValue];
}


void load_cert(char pem[], X509_STORE *cert_store) {
    BIO * bio;
    bio = BIO_new_mem_buf(pem, (int)strlen(pem));
    pinned_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    X509_STORE_add_cert(cert_store, pinned_cert);
    NSLog(@"Imported Certificate: %s",X509_NAME_oneline(X509_get_subject_name(pinned_cert), NULL, 0));


}

/** 
 * Adding the root CA and the intermediary CA certificates to the trust store
 * Example.com has 2 intermediaries in addition to the root CA cert.
 * We need all of them in order to validate the entire chain.
 */
void setup_pinned_ca_certs() {
    
    char root_ca_cert[] = "-----BEGIN CERTIFICATE-----\n"
    "MIICWjCCAcMCAgGlMA0GCSqGSIb3DQEBBAUAMHUxCzAJBgNVBAYTAlVTMRgwFgYD\n"
    "VQQKEw9HVEUgQ29ycG9yYXRpb24xJzAlBgNVBAsTHkdURSBDeWJlclRydXN0IFNv\n"
    "bHV0aW9ucywgSW5jLjEjMCEGA1UEAxMaR1RFIEN5YmVyVHJ1c3QgR2xvYmFsIFJv\n"
    "b3QwHhcNOTgwODEzMDAyOTAwWhcNMTgwODEzMjM1OTAwWjB1MQswCQYDVQQGEwJV\n"
    "UzEYMBYGA1UEChMPR1RFIENvcnBvcmF0aW9uMScwJQYDVQQLEx5HVEUgQ3liZXJU\n"
    "cnVzdCBTb2x1dGlvbnMsIEluYy4xIzAhBgNVBAMTGkdURSBDeWJlclRydXN0IEds\n"
    "b2JhbCBSb290MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCVD6C28FCc6HrH\n"
    "iM3dFw4usJTQGz0O9pTAipTHBsiQl8i4ZBp6fmw8U+E3KHNgf7KXUwefU/ltWJTS\n"
    "r41tiGeA5u2ylc9yMcqlHHK6XALnZELn+aks1joNrI1CqiQBOeacPwGFVw1Yh0X4\n"
    "04Wqk2kmhXBIgD8SFcd5tB8FLztimQIDAQABMA0GCSqGSIb3DQEBBAUAA4GBAG3r\n"
    "GwnpXtlR22ciYaQqPEh346B8pt5zohQDhT37qw4wxYMWM4ETCJ57NE7fQMh017l9\n"
    "3PR2VX2bY1QY6fDq81yx2YtCHrnAlU66+tXifPVoYb+O7AWXX1uw16OFNMQkpw0P\n"
    "lZPvy5TYnh+dXIVtx6quTx8itc2VrbqnzPmrC3p/\n"
    "-----END CERTIFICATE-----";

    
    
    char inter_ca_cert1[]  = "-----BEGIN CERTIFICATE-----\n"
    "MIIERjCCAy6gAwIBAgIEByd1ijANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ\n"
    "RTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD\n"
    "VQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTEyMDcyNTE3NTgyOFoX\n"
    "DTE5MDcyNTE3NTc0NFowbDELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0\n"
    "IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTErMCkGA1UEAxMiRGlnaUNl\n"
    "cnQgSGlnaCBBc3N1cmFuY2UgRVYgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQAD\n"
    "ggEPADCCAQoCggEBAMbM5XPm+9S75S0tMqbf5YE/yc0lSbZxKsPVlDRnogocsF9p\n"
    "pkCxxLeyj9CYpKlBWTrT3JTWPNt0OKRKzE0lgvdKpVMSOO7zSW1xkX5jtqumX8Ok\n"
    "hPhPYlG++MXs2ziS4wblCJEMxChBVfvLWokVfnHoNb9Ncgk9vjo4UFt3MRuNs8ck\n"
    "RZqnrG0AFFoEt7oT61EKmEFBIk5lYYeBQVCmeVyJ3hlKV9Uu5l0cUyx+mM0aBhak\n"
    "aHPQNAQTXKFx01p8VdteZOE3hzBWBOURtCmAEvF5OYiiAhF8J2a3iLd48soKqDir\n"
    "CmTCv2ZdlYTBoSUeh10aUAsgEsxBu24LUTi4S8sCAwEAAaOCAQAwgf0wEgYDVR0T\n"
    "AQH/BAgwBgEB/wIBATBTBgNVHSAETDBKMEgGCSsGAQQBsT4BADA7MDkGCCsGAQUF\n"
    "BwIBFi1odHRwOi8vY3liZXJ0cnVzdC5vbW5pcm9vdC5jb20vcmVwb3NpdG9yeS5j\n"
    "Zm0wDgYDVR0PAQH/BAQDAgEGMB8GA1UdIwQYMBaAFOWdWTCCR1jMrPoIVDaGezq1\n"
    "BE3wMEIGA1UdHwQ7MDkwN6A1oDOGMWh0dHA6Ly9jZHAxLnB1YmxpYy10cnVzdC5j\n"
    "b20vQ1JML09tbmlyb290MjAyNS5jcmwwHQYDVR0OBBYEFLE+w2kD+L9HAdSYJhoI\n"
    "Au9jZCvDMA0GCSqGSIb3DQEBBQUAA4IBAQB2Vlg2DRmYtNmlyzB1rrHWgJfM7jhy\n"
    "aDmwAj5GtsTyrNHS4WYW5oWkVXfLLhxZ3aVL3y8zu85gVyc6oU1Jb1V2bdXXwqBb\n"
    "Kpv5S/d/Id3uXFcNADU68YxGywT2Ro/OBWrVxGz+bpi/pJy9joksvnEBQ8w2KmQG\n"
    "VpeTpUe9Sj+MG3XInrDwJZh3IcB2p1F6JCV9GDUG/sEJxQ47majNnSmwOon16ucq\n"
    "5eIkTmipHafd0ghLodFvDL0s4Lt8+qE8Zc86UkvTIHoKEFX4rUMWVCdOU3PIo5aJ\n"
    "0OF5xgl41fW9sbPFf6ZLr0kRyJecT3xwaRZcLbjQ3xwyUrne88MG6IMi\n"
    "-----END CERTIFICATE-----";

    
    
    char inter_ca_cert2[] ="-----BEGIN CERTIFICATE-----\n"
    "MIIEsTCCA5mgAwIBAgIQBOHnpNxc8vNtwCtCuF0VnzANBgkqhkiG9w0BAQsFADBs\n"
    "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
    "d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5j\n"
    "ZSBFViBSb290IENBMB4XDTEzMTAyMjEyMDAwMFoXDTI4MTAyMjEyMDAwMFowcDEL\n"
    "MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3\n"
    "LmRpZ2ljZXJ0LmNvbTEvMC0GA1UEAxMmRGlnaUNlcnQgU0hBMiBIaWdoIEFzc3Vy\n"
    "YW5jZSBTZXJ2ZXIgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2\n"
    "4C/CJAbIbQRf1+8KZAayfSImZRauQkCbztyfn3YHPsMwVYcZuU+UDlqUH1VWtMIC\n"
    "Kq/QmO4LQNfE0DtyyBSe75CxEamu0si4QzrZCwvV1ZX1QK/IHe1NnF9Xt4ZQaJn1\n"
    "itrSxwUfqJfJ3KSxgoQtxq2lnMcZgqaFD15EWCo3j/018QsIJzJa9buLnqS9UdAn\n"
    "4t07QjOjBSjEuyjMmqwrIw14xnvmXnG3Sj4I+4G3FhahnSMSTeXXkgisdaScus0X\n"
    "sh5ENWV/UyU50RwKmmMbGZJ0aAo3wsJSSMs5WqK24V3B3aAguCGikyZvFEohQcft\n"
    "bZvySC/zA/WiaJJTL17jAgMBAAGjggFJMIIBRTASBgNVHRMBAf8ECDAGAQH/AgEA\n"
    "MA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw\n"
    "NAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy\n"
    "dC5jb20wSwYDVR0fBEQwQjBAoD6gPIY6aHR0cDovL2NybDQuZGlnaWNlcnQuY29t\n"
    "L0RpZ2lDZXJ0SGlnaEFzc3VyYW5jZUVWUm9vdENBLmNybDA9BgNVHSAENjA0MDIG\n"
    "BFUdIAAwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQ\n"
    "UzAdBgNVHQ4EFgQUUWj/kK8CB3U8zNllZGKiErhZcjswHwYDVR0jBBgwFoAUsT7D\n"
    "aQP4v0cB1JgmGggC72NkK8MwDQYJKoZIhvcNAQELBQADggEBABiKlYkD5m3fXPwd\n"
    "aOpKj4PWUS+Na0QWnqxj9dJubISZi6qBcYRb7TROsLd5kinMLYBq8I4g4Xmk/gNH\n"
    "E+r1hspZcX30BJZr01lYPf7TMSVcGDiEo+afgv2MW5gxTs14nhr9hctJqvIni5ly\n"
    "/D6q1UEL2tU2ob8cbkdJf17ZSHwD2f2LSaCYJkJA69aSEaRkCldUxPUd1gJea6zu\n"
    "xICaEnL6VpPX/78whQYwvwt/Tv9XBZ0k7YXDK/umdaisLRbvfXknsuvCnQsH6qqF\n"
    "0wGjIChBWUMo0oHjqvbsezt3tkBigAVBRQHvFwY+3sAzm2fTYS5yh+Rp/BIAV0Ae\n"
    "cPUeybQ=\n"
    "-----END CERTIFICATE-----";

    char inter_ca_cert3[] = "-----BEGIN CERTIFICATE-----\n"
    "MIIEFTCCA36gAwIBAgIEByeO7TANBgkqhkiG9w0BAQUFADB1MQswCQYDVQQGEwJV\n"
    "UzEYMBYGA1UEChMPR1RFIENvcnBvcmF0aW9uMScwJQYDVQQLEx5HVEUgQ3liZXJU\n"
    "cnVzdCBTb2x1dGlvbnMsIEluYy4xIzAhBgNVBAMTGkdURSBDeWJlclRydXN0IEds\n"
    "b2JhbCBSb290MB4XDTEyMDQxODE2MzYxOFoXDTE4MDgxMzE2MzUxN1owWjELMAkG\n"
    "A1UEBhMCSUUxEjAQBgNVBAoTCUJhbHRpbW9yZTETMBEGA1UECxMKQ3liZXJUcnVz\n"
    "dDEiMCAGA1UEAxMZQmFsdGltb3JlIEN5YmVyVHJ1c3QgUm9vdDCCASIwDQYJKoZI\n"
    "hvcNAQEBBQADggEPADCCAQoCggEBAKMEuyKrmD1X6CZymrV51Cni4eiVgLGw41uO\n"
    "KymaZN+hXe2wCQVt2yguzmKiYv60iNoS6zjrIZ3AQSsBUnuId9Mcj8e6uYi1agnn\n"
    "c+gRQKfRzMpijS3ljwumUNKoUMMo6vWrJYeKmpYcqWe4PwzV9/lSEy/CG9VwcPCP\n"
    "wBLKBsua4dnKM3p31vjsufFoREJIE9LAwqSuXmD+tqYF/LTdB1kC1FkYmGP1pWPg\n"
    "kAx9XbIGevOF6uvUA65ehD5f/xXtabz5OTZydc93Uk3zyZAsuT3lySNTPx8kmCFc\n"
    "B5kpvcY67Oduhjprl3RjM71oGDHweI12v/yejl0qhqdNkNwnGjkCAwEAAaOCAUcw\n"
    "ggFDMBIGA1UdEwEB/wQIMAYBAf8CAQMwSgYDVR0gBEMwQTA/BgRVHSAAMDcwNQYI\n"
    "KwYBBQUHAgEWKWh0dHA6Ly9jeWJlcnRydXN0Lm9tbmlyb290LmNvbS9yZXBvc2l0\n"
    "b3J5MA4GA1UdDwEB/wQEAwIBBjCBiQYDVR0jBIGBMH+heaR3MHUxCzAJBgNVBAYT\n"
    "AlVTMRgwFgYDVQQKEw9HVEUgQ29ycG9yYXRpb24xJzAlBgNVBAsTHkdURSBDeWJl\n"
    "clRydXN0IFNvbHV0aW9ucywgSW5jLjEjMCEGA1UEAxMaR1RFIEN5YmVyVHJ1c3Qg\n"
    "R2xvYmFsIFJvb3SCAgGlMEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly93d3cucHVi\n"
    "bGljLXRydXN0LmNvbS9jZ2ktYmluL0NSTC8yMDE4L2NkcC5jcmwwDQYJKoZIhvcN\n"
    "AQEFBQADgYEAkx3+i65G7MupD6vl78qyaBZo2I/6E6mvs8st50tujmkqwisQCo32\n"
    "rnO2ufsU/V9tuFC2xIrWQH7Xw8tz3MldW6+wQbU36+rcIJHENGr0ofOWnTeGl+Fx\n"
    "pN19+kSElK7XCQQidg9kUTWpJA/5C9sy2sL+wbkqXHonE8qxSDpx0EM=\n"
    "-----END CERTIFICATE-----";

    
    X509_STORE * cert_store = X509_STORE_new();
    load_cert(root_ca_cert, cert_store);
    load_cert(inter_ca_cert1, cert_store);
    load_cert(inter_ca_cert2, cert_store);
    load_cert(inter_ca_cert3, cert_store);
    SSL_CTX_set_cert_store(ctx, cert_store);
}


bool start_ssl_connection() {
    // OpenSSL Init
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    ctx = SSL_CTX_new(SSLv23_client_method());
    
//    NSString *path = [[NSBundle mainBundle] pathForResource:@"trust_store" ofType:@"pem"];
//    if(! SSL_CTX_load_verify_locations(ctx, [path UTF8String], NULL)) {
//        NSLog(@"Couldn't load trust store.");
//        return false;
//    }
    
    // load pinned CA certs into trust store
    setup_pinned_ca_certs();

    // Verify that certificate is signed with a trusted CA
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    
    // Root cert must be hit at most 4 certificates up the chain.
    // Have to use this for example.com
    // If you sign the leaf cert directly using your CA, can reduce this value.
    SSL_CTX_set_verify_depth(ctx, 4);

    
    /*
     * Establish the connection
     */
    bio = BIO_new_ssl_connect(ctx);
    
    // automatically handles handshakes after connection is established
    BIO_get_ssl(bio, & ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    
    char server[] = "www.example.org:443";
    BIO_set_conn_hostname(bio, server);
    
    // Check for connection error
    if(bio == NULL) {
        NSLog(@"Connection Error. Handle was NULL.");
        return false;
    }
    
    
    
    // Ensure connection succeeded
    if(BIO_do_connect(bio) <= 0) {
        NSLog(@"Connection Error");
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Additional verification
    return verify_certificate();
}


bool verify_certificate() {
    
    X509 *received_cert = SSL_get_peer_certificate(ssl);

    
    // First lets verify this is a cert in our trust store.
    if(SSL_get_verify_result(ssl)!=X509_V_OK)
    {
        NSLog(@"Certificate doesn't verify. Error: %s", X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        return false;
    }

    // Just for good measure lets check the CN
    char received_cn[256];
    X509_NAME_get_text_by_NID(X509_get_subject_name(received_cert), NID_commonName, received_cn, 256);
    if(![[NSString stringWithCString:received_cn encoding:NSASCIIStringEncoding]  isEqual: @"www.example.org"]) {
        NSLog(@"Unexpected CN: %s",received_cn);
        return false;
    }
    
    // ... and the OU ...
    X509_NAME_get_text_by_NID(X509_get_subject_name(received_cert), NID_organizationalUnitName, received_cn, 256);
    if(![[NSString stringWithCString:received_cn encoding:NSASCIIStringEncoding]  isEqual: @"Technology"]) {
        NSLog(@"Unexpected OU: %s",received_cn);
        return false;
    }

    // ... and the Organization.
    X509_NAME_get_text_by_NID(X509_get_subject_name(received_cert), NID_organizationName, received_cn, 256);
    if(![[NSString stringWithCString:received_cn encoding:NSASCIIStringEncoding]  isEqual: @"Internet Corporation for Assigned Names and Numbers"]) {
        NSLog(@"Unexpected O: %s",received_cn);
        return false;
    }
    return true;
}

- (IBAction)sslRequest:(id)sender {
    // I used the excellent tutorial at http://www.ibm.com/developerworks/library/l-openssl/
    // to implement this piece of code.


    [self label].text = @"Hello";
    [self label].numberOfLines = 0;


    
    // establish connection and verify certificate
    bool success = start_ssl_connection();
    if(!success) {
        [self label].text = @"Error establishing connection";
        return;
    }
    
    /*
     * Finally, lets make the request
     */
    
    // Basic GET request for /
    char request[] = "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n";
    int len = (int) strlen(request);
    
    
    // Write to socket / Send request
    if(BIO_write(bio, request,  len) <= 0) {
        [self label].text = @"Error making request";
        return;
    }
    

    
    // Initalize a response buffer and read from the socket
    NSMutableString *complete_response = [NSMutableString string];
    char response[1024];
    int x;
    
    // read headers
    x = BIO_read(bio, response, 1023);
    int content_length = extract_content_length(response);
    
    // Now that we know the content length, read until we have the entire body..
    while(content_length > 0) {
        x = BIO_read(bio, response, 1023);
        content_length -= x;
        NSLog(@"Received %d bytes. Remaining Bytes: %d", x, content_length);
        
        response[x] = 0;
        [complete_response appendString:[NSString stringWithCString:response encoding:NSASCIIStringEncoding]];
    }
    NSLog(@"Done reading.");
    [self label].text = complete_response;

    BIO_free_all(bio);

    
    
    }

@end
