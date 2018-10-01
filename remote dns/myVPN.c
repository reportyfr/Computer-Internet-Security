//
//  myVPN.c
//  
//
//  Created by Junhua Chen on 2017/4/20.
//
//

#include <unistd.h>
#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <stdlib.h>
#include <string.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <netinet/ip.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define CERTF "client.crt"
#define KEYF "client.key"
#define CACERT "ca.crt"


#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000
#define CLIENT 0
#define SERVER 1
#define PORT 55555
#define HMAC_LEN 32

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

int debug;
char *progname;
char key[];
char IV[];
int result_len;

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

/*--------------------------------------------------------
 the part below is the encryption & decryption section
 ----------------------------------------------------------*/

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    
    int len;
    
    int ciphertext_len;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    
    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 128 bit AES (i.e. a 128 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();
    
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;
    
    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    
    int len;
    
    int plaintext_len;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        printf("decrypt new error\n");
        handleErrors();
    }
    
    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 128 bit AES (i.e. a 128 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        printf("decrypt init error\n");
        handleErrors();
    }
    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        printf("decrypt update error\n");
        handleErrors();
    }
    plaintext_len = len;
    
    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)){
      	 printf("decrypt final error %s,%d\n",plaintext,len);
        handleErrors();
    }
    plaintext_len += len;
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    return plaintext_len;
}

//the next function will do the HMAC
void do_hmac(unsigned char *plaintext, unsigned int plaintext_len, unsigned char *result, unsigned int result_len){
    unsigned char *key = (unsigned char *)"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    
    HMAC_Init_ex(&ctx, key, 16, EVP_sha256(), NULL);
    HMAC_Update(&ctx, plaintext, plaintext_len);
    HMAC_Final(&ctx, result, &result_len);
}

//the next fnction will check if the two hash value are the same 1 for yes 0 for no
int strcompare(unsigned char* str1, unsigned char* str2, unsigned int len){
    int i;
    for(i=0; i!=len; i++){
        if (str1[i]!=str2[i])
        {
            printf("Got %02X instead of %02X at byte %d! The two hash value are not the same!\n", str1[i], str2[i], i);
            break;
        }
    }
    if(i==len){
        printf("Hash Value Test OK!\n");
        return 1;
    }
    else
        return 0;
}

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/

int tun_alloc(char *dev, int flags) {
    
    struct ifreq ifr;
    int fd, err;
    
    if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
        perror("Opening /dev/net/tun");
        return fd;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    
    ifr.ifr_flags = flags;
    
    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }
    
    if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }
    
    strcpy(dev, ifr.ifr_name);
    
    return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
    
    int nread;
    
    if((nread=read(fd, buf, n))<0){
        perror("Reading data");
        exit(1);
    }
    return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
    
    int nwrite;
    
    if((nwrite=write(fd, buf, n))<0){
        perror("Writing data");
        exit(1);
    }
    return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {
    
    int nread, left = n;
    
    while(left > 0) {
        if ((nread = cread(fd, buf, left))==0){
            return 0 ;
        }else {
            left -= nread;
            buf += nread;
        }
    }
    return n;
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){
    
    va_list argp;
    
    if(debug){
        va_start(argp, msg);
        vfprintf(stderr, msg, argp);
        va_end(argp);
    }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {
    
    va_list argp;
    
    va_start(argp, msg);
    vfprintf(stderr, msg, argp);
    va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
    fprintf(stderr, "%s -h\n", progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
    fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
    fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
    fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
    fprintf(stderr, "-d: outputs debug information while running\n");
    fprintf(stderr, "-h: prints this help text\n");
    exit(1);
}



//main function
int main(int argc, char *argv[])
{
    int     fd[2], nbytes;
    pid_t   childpid;
    //char    string[] = "Hello, world!\n";
    char    readbuffer[80];  //for connecion between father process and child process
    
    int tap_fd, option;
    int flags = IFF_TUN;
    char if_name[IFNAMSIZ] = "";
    int header_len = IP_HDR_LEN;
    int maxfd;
    uint16_t nread, nwrite, plength;
    
    char buffer[BUFSIZE];
    char tmp_buffer[BUFSIZE];
    struct sockaddr_in local, remote;
    char remote_ip[16] = "";           //server IP, used for client to sprcify the target address
    char username[16] = "";            //username for client
    char passwd[16] = "";              //password for client
    unsigned short int port = PORT;
    int sock_fd, net_fd, optval = 1;
    socklen_t remotelen;
    int cliserv = -1;    /* must be specified on cmd line */
    unsigned long int tap2net = 0, net2tap = 0;
    
    struct sockaddr_in client;
    int clientlen;
    
    progname = argv[0];
    
    /* Check command line options */
    while((option = getopt(argc, argv, "i:sc:p:uahd")) > 0){
        switch(option) {
            case 'd':
                debug = 1;
                break;
            case 'h':
                usage();
                break;
            case 'i':
                strncpy(if_name,optarg,IFNAMSIZ-1);
                break;
            case 's':
                cliserv = SERVER;
                break;
            case 'c':
                cliserv = CLIENT;
                strncpy(remote_ip,optarg,15);
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'u':
                flags = IFF_TUN;
                break;
            case 'a':
                flags = IFF_TAP;
                header_len = ETH_HDR_LEN;
                break;
            case 'U':
                strncpy(username, optarg, 16);
                break;
            case 'P':
                strncpy(passwd, optarg, 16);
                break;
            default:
                my_err("Unknown option %c\n", option);
                usage();
        }
    }
    
    argv += optind;
    argc -= optind;
    
    if(argc > 0){
        my_err("Too many options!\n");
        usage();
    }
    
    if(*if_name == '\0'){
        my_err("Must specify interface name!\n");
        usage();
    }else if(cliserv < 0){
        my_err("Must specify client or server mode!\n");
        usage();
    }else if((cliserv == CLIENT)&&(*remote_ip == '\0')){
        my_err("Must specify server address!\n");
        usage();
    }
    
    pipe(fd);
    
    if((childpid = fork()) == -1)
    {
        perror("fork");
        exit(1);
    }
    
    /********************************************************************************/
    //the tun program
    /********************************************************************************/
    if(childpid == 0)
    {
        /* Child process closes up input side of pipe */
        close(fd[1]);
        
        /* Send "string" through the output side of pipe */
        //nbytes = read(fd[0], readbuffer, sizeof(readbuffer));
        /* initialize tun/tap interface */
        if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
            my_err("Error connecting to tun/tap interface %s!\n", if_name);
            exit(1);
        }
        
        do_debug("Successfully connected to interface %s\n", if_name);
        /*
         if ( (sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
         perror("socket()");
         exit(1);
         }
         */
        
        //udp socket creation
        if((sock_fd = socket(AF_INET,SOCK_DGRAM, IPPROTO_UDP))<0){
            perror("socket()");
            exit(1);
        }
        
        if(cliserv==CLIENT){
            /* Client, try to connect to server */
            
            /* assign the destination address */
            memset(&remote, 0, sizeof(remote));
            remote.sin_family = AF_INET;
            remote.sin_addr.s_addr = inet_addr(remote_ip);
            remote.sin_port = htons(port);
            
            net_fd=sock_fd;
            do_debug("CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr));
            
        } else {
            /* Server, wait for connections */
            
            /* avoid EADDRINUSE error on bind() */
            if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
                perror("setsockopt()");
                exit(1);
            }
            
            memset(&local, 0, sizeof(local));
            local.sin_family = AF_INET;
            local.sin_addr.s_addr = htonl(INADDR_ANY);
            local.sin_port = htons(port);
            if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0){
                perror("bind()");
                exit(1);
            }
            
            
            remotelen = sizeof(remote);
            memset(&remote, 0, remotelen);
            
            net_fd=sock_fd;
            do_debug("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));
        }
        
        /* use select() to handle two descriptors at once */
        maxfd = (tap_fd > net_fd)?tap_fd:net_fd;
        
        while(1) {
            int ret;
            fd_set rd_set;
            
            FD_ZERO(&rd_set);
            FD_SET(tap_fd, &rd_set); FD_SET(net_fd, &rd_set);
            
            ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);
            
            if (ret < 0 && errno == EINTR){
                continue;
            }
            
            if (ret < 0) {
                perror("select()");
                exit(1);
            }
            
            if(FD_ISSET(tap_fd, &rd_set)){
                /* data from tun/tap: just read it and write it to the network */
                //
                
                
                nread = cread(tap_fd, buffer, BUFSIZE);
                
                //do encrypt
                
                int e_len = encrypt(buffer, nread, key, IV, tmp_buffer);
                char encryptedmes[e_len+HMAC_LEN];
                memcpy(encryptedmes, tmp_buffer, e_len);
                
                //do hash
                unsigned int resultlength;
                unsigned char result[HMAC_LEN];
                do_hmac(encryptedmes, e_len, result, resultlength);
                
                memcpy(encryptedmes+e_len, result, HMAC_LEN);
                
                
                
                tap2net++;
                do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);
                
                
                
                nwrite=sendto(net_fd, encryptedmes, e_len+HMAC_LEN, 0,(struct sockaddr *)&remote,sizeof(remote));
                do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
            }
            
            if(FD_ISSET(net_fd, &rd_set)){
                /* data from the network: read it, and write it to the tun/tap interface.
                 * We need to read the length first, and then the packet */
                
                
                nread=recvfrom(net_fd, buffer, BUFSIZE,0, (struct sockaddr *)&client,&clientlen);
                //remote=client;
                //do_debug("SERVER:Client connected from %s\n", inet_ntoa(client.sin_addr));
                
                if(nread == 0) {
                    /* ctrl-c at the other end */
                    break;
                }
                
                
                net2tap++;
                
                do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);
                remote=client;
                /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */
                
                //decryption
                unsigned char appendedhashvalue[HMAC_LEN];
                unsigned char calculatedhashvalue[HMAC_LEN];
                unsigned char ciptext[nread-HMAC_LEN];
                //get the ciphertext and hashvalue
                //printf("1\n");
                memcpy(ciptext, buffer, nread-HMAC_LEN);
                //printf("2\n");
                memcpy(appendedhashvalue, buffer+nread-HMAC_LEN, HMAC_LEN);
                //printf("3\n");
                //calculate the hash value
                int resultlength;
                unsigned char result[HMAC_LEN];
                printf("nread-HMAC_LEN is %d \n", nread-HMAC_LEN);
                do_hmac(ciptext, nread-HMAC_LEN, result, resultlength);
                //printf("5\n");
                memcpy(calculatedhashvalue, result, HMAC_LEN);
                //printf("6\n");
                
                
                
                if(strcompare(appendedhashvalue, calculatedhashvalue, HMAC_LEN)==1){
                    int d_len = decrypt(ciptext, nread-HMAC_LEN, key, IV, tmp_buffer);
                    char decryptedmes[d_len];
                    memcpy(decryptedmes, tmp_buffer, d_len);
                    
                    nwrite = cwrite(tap_fd, decryptedmes, d_len);
                    
                    do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
                }
                else{
                    exit(1);
                }
            }
            nbytes = read(fd[0], readbuffer, sizeof(readbuffer));
            if(strcmp(nbytes, "quit")==0)
                exit(0);
        }
    }
    
    //the main program
    else
    {
        /* Parent process closes up output side of pipe */
        close(fd[0]);
        
        if(cliserv==CLIENT){                                 //client
            int err;
            int sd;
            struct sockaddr_in sa;
            SSL_CTX* ctx;
            SSL*     ssl;
            X509*    server_cert;
            char*    str;
            char     buf [4096];
            SSL_METHOD *meth;
            
            SSLeay_add_ssl_algorithms();
            meth = SSLv23_client_method();
            SSL_load_error_strings();
            ctx = SSL_CTX_new (meth);
            CHK_NULL(ctx);
            
            CHK_SSL(err);
            
            
            SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
            SSL_CTX_load_verify_locations(ctx,CACERT,NULL);

            /* Create a socket and connect to server using normal socket calls. */
            
            sd = socket (AF_INET, SOCK_STREAM, 0);
            CHK_ERR(sd, "socket");
            
            memset (&sa, '\0', sizeof(sa));
            sa.sin_family      = AF_INET;
            sa.sin_addr.s_addr = inet_addr (remote_ip);   /* Server IP */
            sa.sin_port        = htons     (1111);          /* Server Port number */
            
            err = connect(sd, (struct sockaddr*) &sa,
                          sizeof(sa));
            CHK_ERR(err, "connect");
            
            /* ----------------------------------------------- */
            /* Now we have TCP conncetion. Start SSL negotiation. */
            
            ssl = SSL_new (ctx);
            CHK_NULL(ssl);
            SSL_set_fd (ssl, sd);
            err = SSL_connect (ssl);
            CHK_SSL(err);
            
            /* Following two steps are optional and not required for
             data exchange to be successful. */
            
            /* Get the cipher - opt */
            
            printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
            
            /* Get server's certificate (note: beware of dynamic allocation) - opt */
            
            server_cert = SSL_get_peer_certificate (ssl);
            CHK_NULL(server_cert);
            printf ("Server certificate:\n");
            
            str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
            CHK_NULL(str);
            printf ("\t subject: %s\n", str);
            OPENSSL_free (str);
            
            str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
            CHK_NULL(str);
            printf ("\t issuer: %s\n", str);
            OPENSSL_free (str);
            
            /* We could do all sorts of certificate verification stuff here before
             deallocating the certificate. */
            printf("\tcheck certification successfully!\n");
            
            X509_free (server_cert);
            
            /* --------------------------------------------------- */
            /* DATA EXCHANGE - Send a message and receive a reply. */
            err = SSL_read (ssl, buf, sizeof(buf) - 1);             //get the welcome information from server
            CHK_SSL(err);
            buf[err] = '\0';
            
            //log into the system using the username and password
            printf("passing username and password to the system");
            err = SSL_write (ssl, username, strlen(username));          //send the username and password
            CHK_SSL(err);
            err = SSL_write (ssl, passwd, strlen(passwd));              //send the username and password
            CHK_SSL(err);
            
            err = SSL_read (ssl, buf, sizeof(buf) - 1);                 //get key from server
            CHK_SSL(err);
            strncpy(key, buf, sizeof(buf)-1);
            buf[err] = '\0';
            printf("receiving key and IV from the server");
            
            err = SSL_read (ssl, buf, sizeof(buf) - 1);                 //get IV from server
            CHK_SSL(err);
            strncpy(IV, buf, sizeof(buf)-1);
            buf[err] = '\0';
            
            
            SSL_shutdown (ssl);  /* send SSL/TLS close_notify */
            
            /* Clean up. */
            
            close (sd);
            SSL_free (ssl);
            SSL_CTX_free (ctx);
        
        }
        else
        {                                                //server
            int err;
            int listen_sd;
            int sd;
            struct sockaddr_in sa_serv;
            struct sockaddr_in sa_cli;
            size_t client_len;
            SSL_CTX* ctx;
            SSL*     ssl;
            X509*    client_cert;
            char*    str;
            char     buf [4096];
            SSL_METHOD *meth;
            
            /* SSL preliminaries. We keep the certificate and key with the context. */
            
            SSL_load_error_strings();
            SSLeay_add_ssl_algorithms();
            meth = SSLv23_server_method();
            ctx = SSL_CTX_new (meth);
            if (!ctx) {
                ERR_print_errors_fp(stderr);
                exit(2);
            }
            
            //SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL); /* whether verify the certificate */
            //SSL_CTX_load_verify_locations(ctx,CACERT,NULL);
            
            if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
                ERR_print_errors_fp(stderr);
                exit(3);
            }
            if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
                ERR_print_errors_fp(stderr);
                exit(4);
            }
            
            if (!SSL_CTX_check_private_key(ctx)) {
                fprintf(stderr,"Private key does not match the certificate public key\n");
                exit(5);
            }
            
            /* ----------------------------------------------- */
            /* Prepare TCP socket for receiving connections */
            
            listen_sd = socket (AF_INET, SOCK_STREAM, 0);
            CHK_ERR(listen_sd, "socket");
            
            memset (&sa_serv, '\0', sizeof(sa_serv));
            sa_serv.sin_family      = AF_INET;
            sa_serv.sin_addr.s_addr = INADDR_ANY;
            sa_serv.sin_port        = htons (1111);          /* Server Port number */
            
            err = bind(listen_sd, (struct sockaddr*) &sa_serv,
                       sizeof (sa_serv));
            CHK_ERR(err, "bind");
            
            /* Receive a TCP connection. */
            
            err = listen (listen_sd, 5);
            CHK_ERR(err, "listen");
            
            client_len = sizeof(sa_cli);
            sd = accept (listen_sd, (struct sockaddr*) &sa_cli, &client_len);
            CHK_ERR(sd, "accept");
            close (listen_sd);
            
            printf ("Connection from %lx, port %x\n",
                    sa_cli.sin_addr.s_addr, sa_cli.sin_port);
            
            /* ----------------------------------------------- */
            /* TCP connection is ready. Do server side SSL. */
            
            ssl = SSL_new (ctx);
            CHK_NULL(ssl);
            SSL_set_fd (ssl, sd);
            err = SSL_accept (ssl);
            CHK_SSL(err);
            
            /* Get the cipher - opt */
            
            printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
            
            /* Get client's certificate (note: beware of dynamic allocation) - opt */
            
            client_cert = SSL_get_peer_certificate (ssl);
            if (client_cert != NULL) {
                printf ("Client certificate:\n");
                
                str = X509_NAME_oneline (X509_get_subject_name (client_cert), 0, 0);
                CHK_NULL(str);
                printf ("\t subject: %s\n", str);
                OPENSSL_free (str);
                
                str = X509_NAME_oneline (X509_get_issuer_name  (client_cert), 0, 0);
                CHK_NULL(str);
                printf ("\t issuer: %s\n", str);
                OPENSSL_free (str);
                
                /* We could do all sorts of certificate verification stuff here before
                 deallocating the certificate. */
                
                X509_free (client_cert);
            }
            else
                printf ("Client does not have certificate.\n");
            
            /* DATA EXCHANGE - Receive message and send reply. */
            err = SSL_write (ssl, "please send the username and password", strlen("please send the username and password"));          //send welcome information to client
            CHK_SSL(err);
            
            err = SSL_read (ssl, buf, sizeof(buf) - 1);
            CHK_SSL(err);
            if(strcmp(buf, "root")!=0)
            {
                err = SSL_write (ssl, "incorrect username", strlen("incorrect username"));
                CHK_SSL(err);
                exit(10);
            }
            buf[err] = '\0';
            
            err = SSL_read (ssl, buf, sizeof(buf) - 1);
            CHK_SSL(err);
            if(strcmp(buf, "root")!=0)
            {
                err = SSL_write (ssl, "incorrect password", strlen("incorrect password"));
                CHK_SSL(err);
                exit(10);
            }
            buf[err] = '\0';
            
            printf("generating the key and IV...");
            printf("sending key and IV to client");
            
            //generate random number
            srand((unsigned) time(NULL));
            int i,number;
            for(i=0;i<16;i++){
                number = rand() % 128;
                key[i] = number;
                number = rand() % 128;
                IV[i] = number;
            }
            err = SSL_write (ssl, key, strlen(key));          //send key
            CHK_SSL(err);
            err = SSL_write (ssl, IV, strlen(IV));          //send IV
            CHK_SSL(err);
            
            /* Clean up. */
            close (sd);
            SSL_free (ssl);
            SSL_CTX_free (ctx);
        }
        
        /* Read in a string from the pipe */
        //write(fd[1], string, (strlen(string)+1));
        //printf("Received string: %s", readbuffer);
    }
    
    return(0);
}
/* EOF - cli.cpp */

