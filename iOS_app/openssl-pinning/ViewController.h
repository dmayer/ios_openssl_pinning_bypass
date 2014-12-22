//
//  ViewController.h
//  openssl-pinning
//
//  Created by Daniel Mayer on 12/17/14.
//  Copyright (c) 2014 Daniel A. Mayer. All rights reserved.
//

#import <UIKit/UIKit.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <openssl/pem.h>
#include "openssl/bio.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>


    
// OpenSSL and BIO object
BIO * bio;
SSL * ssl;
SSL_CTX * ctx;

// Pinned Cert
X509 * pinned_cert;






@interface ViewController : UIViewController


@end

